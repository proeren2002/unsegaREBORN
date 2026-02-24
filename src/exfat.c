#include "exfat.h"

#define EXFAT_IO_SIZE (1024 * 1024)

static uint64_t get_cluster_offset(ExfatContext* ctx, uint32_t cluster) {
    if (cluster < 2) return 0;
    return ctx->cluster_heap_offset_bytes + ((uint64_t)(cluster - 2) * ctx->bytes_per_cluster);
}

static bool exfat_read(ExfatContext* ctx, void* buffer, uint64_t offset, size_t size) {
    if (ctx->stream) {
        return stream_read(ctx->stream, buffer, offset, size);
    }
    if (ctx->raw_file_pos != offset) {
        if (FSEEKO(ctx->fp, offset, SEEK_SET) != 0) {
            return false;
        }
    }
    if (fread(buffer, 1, size, ctx->fp) != size) {
        return false;
    }
    ctx->raw_file_pos = offset + size;
    return true;
}

static bool read_cluster(ExfatContext* ctx, uint32_t cluster, void* buffer) {
    uint64_t offset = get_cluster_offset(ctx, cluster);
    return exfat_read(ctx, buffer, offset, ctx->bytes_per_cluster);
}

static uint32_t get_next_cluster(ExfatContext* ctx, uint32_t cluster) {
    uint32_t max_cluster = ctx->fat_length_bytes / sizeof(uint32_t);
    if (cluster >= max_cluster) {
        return 0;
    }
    uint32_t next = ctx->fat[cluster];
    if (next >= 0xFFFFFFF8) {
        return 0;
    }
    if (next == 0) return 0;
    if (next >= max_cluster) {
        return 0;
    }
    return next;
}

static bool combine_path(char* dest, size_t dest_size, const char* dir, const char* name) {
    if (!dest || dest_size == 0 || !dir || !name) {
        return false;
    }

    if (!is_safe_path(name)) {
        return false;
    }

    size_t dir_len = strlen(dir);
    size_t name_len = strlen(name);
    size_t sep_len = (dir_len > 0 && dir[dir_len - 1] != '/' && dir[dir_len - 1] != '\\') ? 1 : 0;

    if (dir_len + sep_len + name_len + 1 > dest_size) {
        return false;
    }

    STRCPY_S(dest, dest_size, dir);
    if (sep_len) {
        STRCAT_S(dest, dest_size, PATH_SEPARATOR);
    }
    STRCAT_S(dest, dest_size, name);
    return true;
}

static void update_cached_dir(ExfatContext* ctx, const char* output_path) {
    char parent[MAX_PATH_LENGTH];
    strncpy(parent, output_path, sizeof(parent) - 1);
    parent[sizeof(parent) - 1] = '\0';
    char* sep = strrchr(parent, PATH_SEP_CHAR);
    if (!sep) return;
    *sep = '\0';
    if (strcmp(parent, ctx->last_dir) == 0) return;
    close_output_dir(ctx->cached_dir);
    ctx->cached_dir = open_output_dir(parent);
    strncpy(ctx->last_dir, parent, MAX_PATH_LENGTH - 1);
    ctx->last_dir[MAX_PATH_LENGTH - 1] = '\0';
}

static bool extract_file(ExfatContext* ctx, ExfatFileInfo* file, const char* output_path) {
    update_cached_dir(ctx, output_path);

    FILE* out = NULL;
    if (ctx->cached_dir != INVALID_DIR_HANDLE) {
        out = fopen_in_dir(ctx->cached_dir, file->name, file->data_length >= 65536 ? file->data_length : 0);
    }
    if (!out) {
        if (file->data_length >= 65536) {
            out = FOPEN_PREALLOC(output_path, file->data_length);
        } else {
            out = FOPEN(output_path, "wb");
        }
    }
    if (!out) {
        return false;
    }

    uint64_t remaining = file->data_length;
    bool success = true;

    if (file->no_fat_chain) {
        uint64_t offset = get_cluster_offset(ctx, file->first_cluster);
        while (remaining > 0 && success) {
            size_t chunk = (remaining > EXFAT_IO_SIZE) ? EXFAT_IO_SIZE : (size_t)remaining;
            if (!exfat_read(ctx, ctx->io_buf, offset, chunk)) {
                success = false;
                break;
            }
            if (FWRITE_DIRECT(out, ctx->io_buf, chunk) != chunk) {
                success = false;
                break;
            }
            offset += chunk;
            remaining -= chunk;
            ctx->extracted_bytes += chunk;
        }
    } else {
        uint32_t max_clusters = (uint32_t)((file->data_length + ctx->bytes_per_cluster - 1) / ctx->bytes_per_cluster);
        uint32_t cluster_count = 0;
        uint32_t current_cluster = file->first_cluster;
        while (remaining > 0 && current_cluster != 0 && success) {
            if (++cluster_count > max_clusters) break;
            size_t chunk = (remaining > ctx->bytes_per_cluster) ? ctx->bytes_per_cluster : (size_t)remaining;
            uint64_t offset = get_cluster_offset(ctx, current_cluster);
            if (!exfat_read(ctx, ctx->io_buf, offset, chunk)) {
                success = false;
                break;
            }
            if (FWRITE_DIRECT(out, ctx->io_buf, chunk) != chunk) {
                success = false;
                break;
            }
            remaining -= chunk;
            current_cluster = get_next_cluster(ctx, current_cluster);
            ctx->extracted_bytes += chunk;
        }
    }

    if (success && file->modify_timestamp != 0) {
        uint64_t mtime = exfat_timestamp_to_ntfs(file->modify_timestamp, file->modify_10ms, file->modify_utc_offset);
        uint64_t atime = exfat_timestamp_to_ntfs(file->access_timestamp, 0, file->access_utc_offset);
#ifdef _WIN32
        set_file_times_handle(out, mtime, atime);
#endif
    }

    fclose(out);

    if (success) {
        ctx->files_extracted++;
#ifndef _WIN32
        if (file->modify_timestamp != 0) {
            uint64_t mtime = exfat_timestamp_to_ntfs(file->modify_timestamp, file->modify_10ms, file->modify_utc_offset);
            uint64_t atime = exfat_timestamp_to_ntfs(file->access_timestamp, 0, file->access_utc_offset);
            set_file_times(output_path, mtime, atime);
        }
#endif
    }

    return success;
}

#define EXFAT_MAX_RECURSION_DEPTH 128

static bool process_directory_recursive(ExfatContext* ctx, uint32_t start_cluster, const char* output_dir, int depth) {
    if (depth > EXFAT_MAX_RECURSION_DEPTH) {
        fprintf(stderr, "depth\n");
        return true;
    }

    uint32_t total_clusters = 0;
    uint32_t cluster = start_cluster;
    while (cluster != 0 && total_clusters < ctx->boot_sector.cluster_count) {
        total_clusters++;
        cluster = get_next_cluster(ctx, cluster);
    }
    if (total_clusters == 0) return true;

    uint64_t total_size = (uint64_t)total_clusters * ctx->bytes_per_cluster;
    uint8_t* dir_buf = malloc((size_t)total_size);
    if (!dir_buf) return false;

    cluster = start_cluster;
    for (uint32_t c = 0; c < total_clusters; c++) {
        if (cluster == 0) { free(dir_buf); return false; }
        uint64_t offset = get_cluster_offset(ctx, cluster);
        if (!exfat_read(ctx, dir_buf + (uint64_t)c * ctx->bytes_per_cluster, offset, ctx->bytes_per_cluster)) {
            free(dir_buf);
            return false;
        }
        cluster = get_next_cluster(ctx, cluster);
    }

    uint32_t total_entries = (uint32_t)(total_size / EXFAT_ENTRY_SIZE);
    uint32_t idx = 0;

    while (idx < total_entries) {
        uint8_t* entry_ptr = dir_buf + (uint64_t)idx * EXFAT_ENTRY_SIZE;
        uint8_t entry_type = *entry_ptr;

        if (entry_type == EXFAT_ENTRY_EOD) break;

        if (entry_type == EXFAT_ENTRY_FILE) {
            if (idx + 2 > total_entries) { idx++; continue; }

            ExfatFileEntry* file_entry = (ExfatFileEntry*)entry_ptr;
            ExfatStreamEntry* stream_entry = (ExfatStreamEntry*)(entry_ptr + EXFAT_ENTRY_SIZE);
            if (stream_entry->entry_type != EXFAT_ENTRY_STREAM) {
                idx++;
                continue;
            }

            int total_name_chars = stream_entry->name_length;
            int num_name_entries = (total_name_chars + 14) / 15;
            int set_size = 2 + num_name_entries;

            if (idx + set_size > total_entries) { idx++; continue; }

            char full_name[MAX_FILENAME_LENGTH];
            uint16_t full_name_unicode[MAX_FILENAME_LENGTH];
            int pos = 0;
            uint8_t* name_entry_ptr = entry_ptr + EXFAT_ENTRY_SIZE * 2;
            for (int k = 0; k < num_name_entries; k++) {
                ExfatFileNameEntry* name_entry = (ExfatFileNameEntry*)(name_entry_ptr + k * EXFAT_ENTRY_SIZE);
                int chars_in_this_entry = (total_name_chars - k * 15 < 15) ? (total_name_chars - k * 15) : 15;
                for (int j = 0; j < chars_in_this_entry; j++) {
                    if (pos < MAX_FILENAME_LENGTH - 1) {
                        full_name_unicode[pos++] = name_entry->file_name[j];
                    }
                }
            }
            full_name_unicode[pos] = 0;

            fs_name_to_utf8(full_name_unicode, pos, full_name, sizeof(full_name));

            ExfatFileInfo file_info;
            memset(&file_info, 0, sizeof(file_info));
            strncpy(file_info.name, full_name, MAX_PATH_LENGTH - 1);
            file_info.name[MAX_PATH_LENGTH - 1] = '\0';

            if (file_entry->file_attributes & 0x04) {
                idx += set_size;
                continue;
            }

            file_info.first_cluster = stream_entry->first_cluster;
            file_info.data_length = stream_entry->data_length;
            file_info.is_directory = ((file_entry->file_attributes & 0x10) != 0);
            file_info.no_fat_chain = ((stream_entry->flags & 0x02) != 0);
            file_info.modify_timestamp = file_entry->last_modified_timestamp;
            file_info.access_timestamp = file_entry->last_access_timestamp;
            file_info.modify_10ms = file_entry->last_modified_10ms;
            file_info.modify_utc_offset = (int8_t)file_entry->last_modified_utc_offset;
            file_info.access_utc_offset = (int8_t)file_entry->last_access_utc_offset;

            char full_path[MAX_PATH_LENGTH];
            if (!combine_path(full_path, sizeof(full_path), output_dir, file_info.name)) {
                fprintf(stderr, "path:%s\n", file_info.name);
                idx += set_size;
                continue;
            }

            idx += set_size;

            if (file_info.is_directory) {
                if (create_directories(full_path)) {
                    process_directory_recursive(ctx, file_info.first_cluster, full_path, depth + 1);
                    if (file_info.modify_timestamp != 0) {
                        if (ctx->deferred_count >= ctx->deferred_capacity)
                            grow_deferred_dirs(&ctx->deferred_dirs, &ctx->deferred_capacity);
                        if (ctx->deferred_count < ctx->deferred_capacity) {
                            DeferredDirTime* d = &ctx->deferred_dirs[ctx->deferred_count++];
                            STRCPY_S(d->path, sizeof(d->path), full_path);
                            d->mtime = exfat_timestamp_to_ntfs(file_info.modify_timestamp, file_info.modify_10ms, file_info.modify_utc_offset);
                            d->atime = exfat_timestamp_to_ntfs(file_info.access_timestamp, 0, file_info.access_utc_offset);
                        }
                    }
                }
            }
            else {
                extract_file(ctx, &file_info, full_path);
            }
            continue;
        }
        else {
            idx++;
        }
    }

    free(dir_buf);
    return true;
}

static bool exfat_setup_fields(ExfatContext* ctx) {
    ctx->cached_dir = INVALID_DIR_HANDLE;

    if (ctx->boot_sector.bytes_per_sector_shift < 9 || ctx->boot_sector.bytes_per_sector_shift > 12) return false;
    if (ctx->boot_sector.sectors_per_cluster_shift > 25 - ctx->boot_sector.bytes_per_sector_shift) return false;

    ctx->bytes_per_sector = (1 << ctx->boot_sector.bytes_per_sector_shift);
    ctx->bytes_per_cluster = ctx->bytes_per_sector * (1 << ctx->boot_sector.sectors_per_cluster_shift);
    if (ctx->bytes_per_cluster == 0) return false;

    if (ctx->boot_sector.fat_offset > (0xFFFFFFFFU / ctx->bytes_per_sector)) return false;
    if (ctx->boot_sector.cluster_heap_offset > (0xFFFFFFFFU / ctx->bytes_per_sector)) return false;
    if (ctx->boot_sector.fat_length > (0xFFFFFFFFU / ctx->bytes_per_sector)) return false;

    ctx->cluster_heap_offset_bytes = ctx->boot_sector.cluster_heap_offset * ctx->bytes_per_sector;
    ctx->fat_offset_bytes = ctx->boot_sector.fat_offset * ctx->bytes_per_sector;
    ctx->fat_length_bytes = ctx->boot_sector.fat_length * ctx->bytes_per_sector;

    if (ctx->fat_length_bytes == 0 || ctx->fat_length_bytes > (1U << 30)) return false;

    ctx->fat = malloc(ctx->fat_length_bytes);
    ctx->cluster_buf = malloc(ctx->bytes_per_cluster);
    ctx->io_buf = malloc(EXFAT_IO_SIZE);
    if (!ctx->fat || !ctx->cluster_buf || !ctx->io_buf) {
        free(ctx->fat);
        free(ctx->cluster_buf);
        free(ctx->io_buf);
        return false;
    }
    return true;
}

bool exfat_init(ExfatContext* ctx, const char* filename) {
    memset(ctx, 0, sizeof(ExfatContext));

    ctx->fp = FOPEN(filename, "rb");
    if (!ctx->fp) return false;

    if (fread(&ctx->boot_sector, sizeof(ExfatBootSector), 1, ctx->fp) != 1) {
        fclose(ctx->fp);
        return false;
    }

    if (!exfat_setup_fields(ctx)) {
        fclose(ctx->fp);
        return false;
    }

    if (FSEEKO(ctx->fp, ctx->fat_offset_bytes, SEEK_SET) != 0 ||
        fread(ctx->fat, 1, ctx->fat_length_bytes, ctx->fp) != ctx->fat_length_bytes) {
        exfat_close(ctx);
        return false;
    }

    return true;
}

bool exfat_init_stream(ExfatContext* ctx, DecryptStream* stream) {
    memset(ctx, 0, sizeof(ExfatContext));
    ctx->stream = stream;

    if (!exfat_read(ctx, &ctx->boot_sector, 0, sizeof(ExfatBootSector))) {
        return false;
    }

    if (!exfat_setup_fields(ctx)) return false;

    if (!exfat_read(ctx, ctx->fat, ctx->fat_offset_bytes, ctx->fat_length_bytes)) {
        exfat_close(ctx);
        return false;
    }

    return true;
}

bool exfat_extract_all(ExfatContext* ctx, const char* output_dir) {
    if (!create_directories(output_dir)) {
        return false;
    }

    ctx->extracted_bytes = 0;

    bool result = process_directory_recursive(ctx, ctx->boot_sector.first_cluster_of_root_dir, output_dir, 0);

    for (uint32_t i = ctx->deferred_count; i > 0; i--) {
        DeferredDirTime* d = &ctx->deferred_dirs[i - 1];
        set_dir_times(d->path, d->mtime, d->atime);
    }
    free(ctx->deferred_dirs);
    ctx->deferred_dirs = NULL;
    ctx->deferred_count = 0;
    ctx->deferred_capacity = 0;

    return result;
}

void exfat_close(ExfatContext* ctx) {
    close_output_dir(ctx->cached_dir);
    ctx->cached_dir = INVALID_DIR_HANDLE;
    if (!ctx->stream && ctx->fp) {
        fclose(ctx->fp);
        ctx->fp = NULL;
    }
    if (ctx->fat) {
        free(ctx->fat);
        ctx->fat = NULL;
    }
    free(ctx->cluster_buf);
    ctx->cluster_buf = NULL;
    free(ctx->io_buf);
    ctx->io_buf = NULL;
}
