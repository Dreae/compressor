#include <archive.h>
#include <archive_entry.h>
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

void fetch_and_unpack_maxmind(CURL *curl_handle);
void copy_data(struct archive *a, struct archive *ext);

static size_t write_data_to_file(void *ptr, size_t size, size_t nmemb, void *stream) {
    return fwrite(ptr, size, nmemb, (FILE *)stream);
}

int compare_md5s(FILE *new, FILE *current) {
    if (current == NULL || new == NULL) {
        return 0;
    }

    char current_csum[64];
    char new_csum[64];
    size_t current_csum_size = fread(&current_csum, sizeof(char), 64, current);
    size_t new_csum_size = fread(&new_csum, sizeof(char), 64, new);

    if (current_csum_size != new_csum_size) {
        // This is invalid, so just refetch
        return 0;
    }

    return !memcmp(new_csum, current_csum, current_csum_size);
}

void compressor_update_maxmind(void) {
    curl_global_init(CURL_GLOBAL_ALL);
    CURL *curl_handle = curl_easy_init();

    curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_data_to_file);
    curl_easy_setopt(curl_handle, CURLOPT_URL, "https://geolite.maxmind.com/download/geoip/database/GeoLite2-ASN-CSV.zip.md5");
    FILE *buff = tmpfile();
    if (!buff) {
        fprintf(stderr, "Error updating maxmind database\n");
        perror("tmpfile()");
        exit(1);
    }

    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, buff);
    if (curl_easy_perform(curl_handle) != CURLE_OK) {
        fprintf(stderr, "Error fetching latest maxmind version\n");
        exit(1);
    }

    rewind(buff);

    if (access("/etc/compressor/maxmind_asn.csv.md5", R_OK) != -1) {
        FILE *current_csum = fopen("/etc/compressor/maxmind_asn.csv.md5", "r");
        if (!current_csum) {
            fprintf(stderr, "Error reading current maxmind version\n");
            perror("fopen()");
        }

        if (!compare_md5s(buff, current_csum)) {
            printf("Downloading updated maxmind database...\n");
            fetch_and_unpack_maxmind(curl_handle);
        } else {
            printf("Maxmind database up-to-date\n");
        }
        fclose(current_csum);
    } else {
        printf("Downloading maxmind database...\n");
        fetch_and_unpack_maxmind(curl_handle);
    }

    FILE *current_csum = fopen("/etc/compressor/maxmind_asn.csv.md5", "w");
    if (!current_csum) {
        fprintf(stderr, "Error updating current maxmind version\n");
        perror("fopen()");
        exit(1);
    }
    rewind(buff);

    char ch;
    while ((ch = fgetc(buff)) != EOF) {
        fputc(ch, current_csum);
    }

    curl_easy_cleanup(curl_handle);
    curl_global_cleanup();
}

void fetch_and_unpack_maxmind(CURL *curl_handle) {
    FILE *temp = tmpfile();
    if (!temp) {
        fprintf(stderr, "Error updating maxmind database\n");
        perror("tmpfile()");
        exit(1);
    }

    curl_easy_setopt(curl_handle, CURLOPT_URL, "https://geolite.maxmind.com/download/geoip/database/GeoLite2-ASN-CSV.zip");
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, temp);
    if (curl_easy_perform(curl_handle) != CURLE_OK) {
        fprintf(stderr, "Error downloading latest maxmind database\n");
        exit(1);
    }
    
    rewind(temp);

    struct archive *a = archive_read_new();
    archive_read_support_format_all(a);
    archive_read_support_filter_all(a);

    struct archive *ext = archive_write_disk_new();
    archive_write_disk_set_standard_lookup(ext);
    int r = archive_read_open_FILE(a, temp);
    if (r != ARCHIVE_OK) {
        fprintf(stderr, "Error reading maxmind archive\n");
        exit(1);
    }

    struct archive_entry *entry;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        if (strstr(archive_entry_pathname(entry), "IPv4.csv")) {
            archive_entry_set_pathname(entry, "/etc/compressor/maxmind_asn.csv");
            if (archive_write_header(ext, entry) == ARCHIVE_OK) {
                copy_data(a, ext);
            } else {
                fprintf(stderr, "Error extracting maxmind archive");
                exit(1);
            }

            break;
        }
    }

    archive_read_close(a);
    archive_read_free(a);
    archive_write_close(ext);
    archive_write_free(ext);
}

void copy_data(struct archive *ar, struct archive *aw) {
    for (;;) {
        const void *buff;
        size_t size;
        la_int64_t offset;
        int r = archive_read_data_block(ar, &buff, &size, &offset);
        if (r == ARCHIVE_EOF) {
            return;
        } else if (r < ARCHIVE_OK) {
            fprintf(stderr, "Error extracting maxmind CSV\n");
            exit(1);
        }

        r = archive_write_data_block(aw, buff, size, offset);
        if (r < ARCHIVE_OK) {
            fprintf(stderr, "%s\n", archive_error_string(aw));
            exit(1);
        }
    }
}