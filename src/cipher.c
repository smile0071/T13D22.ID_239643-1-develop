#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifdef USE_OPENSSL
#include <openssl/des.h>
#endif
#include "logger.h"

/* new helper functions for safe log message construction */
static void log_path_level(FILE* log, enum log_level lvl, const char* label, const char* path) {
    if (!log || !label || !path) return;
    size_t n = strlen(label) + 2 + strlen(path);
    char* msg = (char*)malloc(n + 1);
    if (!msg) return;
    snprintf(msg, n + 1, "%s: %s", label, path);
    logcat(log, msg, lvl);
    free(msg);
}

static void log_error_open(FILE* log, const char* path, const char* err) {
    if (!log || !path || !err) return;
    const char* prefix = "Failed to open file";
    size_t n = strlen(prefix) + 2 + strlen(path) + 3 + strlen(err);
    char* msg = (char*)malloc(n + 1);
    if (!msg) return;
    snprintf(msg, n + 1, "%s: %s (%s)", prefix, path, err);
    logcat(log, msg, LOG_ERROR);
    free(msg);
}

int main(void) {
    int cmd;
    char path[4096];
    char current_path[4096] = {0};
    FILE* log = log_init("cipher.log");
    /* log may be NULL if file cannot be opened; code proceeds but logging skipped */
    while (1) {
        if (scanf("%d", &cmd) != 1) {
            break;
        }
        if (cmd == -1) {
            if (log) {
                logcat(log, "Exit command received", LOG_INFO);
            }
            break;
        }

        if (cmd == 1) {
            /* read path token */
            if (scanf(" %4095s", path) != 1) {
                if (log) {
                    logcat(log, "Failed to read path token", LOG_ERROR);
                }
                printf("n/a\n");
                continue;
            }
            if (strcmp(path, "-1") == 0) {
                if (log) {
                    logcat(log, "Exit command received in path input", LOG_INFO);
                }
                break;
            }

            FILE* f = fopen(path, "rb");
            if (!f) {
                if (log) {
                    /* replaced large snprintf with safe helper */
                    log_error_open(log, path, strerror(errno));
                }
                /* clear current file if failed to load */
                current_path[0] = '\0';
                printf("n/a\n");
                continue;
            }
            if (log) {
                log_path_level(log, LOG_INFO, "Opened file", path);
            }

            /* remember loaded path on fopen success (even if file is empty) */
            strncpy(current_path, path, sizeof(current_path) - 1);
            current_path[sizeof(current_path) - 1] = '\0';

            if (fseek(f, 0, SEEK_END) != 0) {
                fclose(f);
                printf("n/a\n");
                continue;
            }
            long sz = ftell(f);
            if (sz <= 0) {
                fclose(f);
                printf("n/a\n");
                continue;
            }
            rewind(f);

            char* buf = (char*)malloc((size_t)sz + 1);
            if (!buf) {
                fclose(f);
                printf("n/a\n");
                continue;
            }

            size_t read = fread(buf, 1, (size_t)sz, f);
            fclose(f);
            if (read != (size_t)sz) {
                free(buf);
                printf("n/a\n");
                continue;
            }
            buf[sz] = '\0';

            fwrite(buf, 1, read, stdout);
            free(buf);

        } else if (cmd == 2) {
            /* consume single newline left after reading cmd */
            int c = getchar();
            if (c != '\n' && c != EOF) {
                ungetc(c, stdin);
            }

            /* read arbitrary line (may contain spaces) */
            char line[8192];
            if (fgets(line, sizeof(line), stdin) == NULL) {
                printf("n/a\n");
                continue;
            }
            /* trim trailing newline/carriage returns */
            size_t ln = strlen(line);
            while (ln > 0 && (line[ln - 1] == '\n' || line[ln - 1] == '\r')) {
                line[--ln] = '\0';
            }
            if (strcmp(line, "-1") == 0) {
                if (log) {
                    logcat(log, "Exit command received in line input", LOG_INFO);
                }
                break;
            }

            if (current_path[0] == '\0') {
                if (log) {
                    logcat(log, "Attempt to write without loaded file", LOG_WARNING);
                }
                /* no file loaded */
                printf("n/a\n");
                continue;
            }

            /* determine whether we need to insert separator newline */
            int need_sep = 0;
            FILE* frcheck = fopen(current_path, "rb");
            if (!frcheck) {
                printf("n/a\n");
                continue;
            }
            if (fseek(frcheck, 0, SEEK_END) != 0) {
                fclose(frcheck);
                printf("n/a\n");
                continue;
            }
            long fend = ftell(frcheck);
            if (fend < 0) {
                fclose(frcheck);
                printf("n/a\n");
                continue;
            }
            if (fend > 0) {
                if (fseek(frcheck, fend - 1, SEEK_SET) != 0) {
                    fclose(frcheck);
                    printf("n/a\n");
                    continue;
                }
                int last = fgetc(frcheck);
                if (last == EOF && ferror(frcheck)) {
                    fclose(frcheck);
                    printf("n/a\n");
                    continue;
                }
                if (last != '\n' && last != '\r') need_sep = 1;
            }
            fclose(frcheck);

            /* append deterministically */
            FILE* fa = fopen(current_path, "ab");
            if (!fa) {
                if (log) {
                    log_path_level(log, LOG_ERROR, "Failed to open for append", current_path);
                }
                printf("n/a\n");
                continue;
            }
            if (need_sep) {
                if (fwrite("\n", 1, 1, fa) != 1) {
                    fclose(fa);
                    printf("n/a\n");
                    continue;
                }
            }
            size_t llen = strlen(line);
            if (llen > 0) {
                if (fwrite(line, 1, llen, fa) != llen) {
                    fclose(fa);
                    printf("n/a\n");
                    continue;
                }
            }
            if (fwrite("\n", 1, 1, fa) != 1) {
                fclose(fa);
                printf("n/a\n");
                continue;
            }
            if (fflush(fa) != 0) {
                fclose(fa);
                printf("n/a\n");
                continue;
            }
            fclose(fa);
            if (log) {
                log_path_level(log, LOG_INFO, "Wrote line to file", current_path);
            }

            /* now output the full file contents */
            FILE* fr = fopen(current_path, "rb");
            if (!fr) {
                printf("n/a\n");
                continue;
            }
            if (fseek(fr, 0, SEEK_END) != 0) {
                fclose(fr);
                printf("n/a\n");
                continue;
            }
            long sz = ftell(fr);
            if (sz <= 0) {
                fclose(fr);
                printf("n/a\n");
                continue;
            }
            rewind(fr);

            char* buf = (char*)malloc((size_t)sz + 1);
            if (!buf) {
                fclose(fr);
                printf("n/a\n");
                continue;
            }
            size_t read = fread(buf, 1, (size_t)sz, fr);
            fclose(fr);
            if (read != (size_t)sz) {
                free(buf);
                printf("n/a\n");
                continue;
            }
            buf[sz] = '\0';
            fwrite(buf, 1, read, stdout);
            free(buf);
        } else if (cmd == 3) {
            /* read integer shift parameter */
            int shift;
            if (scanf("%d", &shift) != 1) {
                if (log) {
                    logcat(log, "Failed to read shift parameter for Caesar", LOG_ERROR);
                }
                printf("n/a\n");
                continue;
            }
            if (shift == -1) {
                if (log) {
                    logcat(log, "Exit command received in Caesar shift input", LOG_INFO);
                }
                break;
            }
            if (log) {
                char msg[512];
                snprintf(msg, sizeof(msg), "Starting Caesar encryption with shift=%d", shift);
                logcat(log, msg, LOG_INFO);
            }

            /* try both possible relative paths: run from repo root or from build/ */
            const char* paths[] = {"src/ai_modules", "../src/ai_modules"};
            const char* selected_path = NULL;
            DIR* d = NULL;
            for (size_t pi = 0; pi < sizeof(paths) / sizeof(paths[0]); ++pi) {
                d = opendir(paths[pi]);
                if (d) {
                    selected_path = paths[pi];
                    break;
                }
            }
            if (!d || !selected_path) {
                if (log) {
                    logcat(log, "Failed to open ai_modules directory for Caesar", LOG_ERROR);
                }
                printf("n/a\n");
                continue;
            }

            struct dirent* entry;
            bool error = false;
            char filepath[8192];

            while ((entry = readdir(d)) != NULL) {
                /* skip . and .. */
                if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

                /* build full path using the actually opened directory */
                if ((size_t)snprintf(filepath, sizeof(filepath), "%s/%s", selected_path, entry->d_name) >=
                    sizeof(filepath)) {
                    error = true;
                    break;
                }

                struct stat st;
                if (stat(filepath, &st) != 0) {
                    /* skip non-stat-able entries */
                    continue;
                }
                if (!S_ISREG(st.st_mode)) continue;

                size_t namelen = strlen(entry->d_name);
                if (namelen >= 2 && strcmp(entry->d_name + namelen - 2, ".h") == 0) {
                    /* truncate .h file */
                    FILE* fh = fopen(filepath, "w");
                    if (!fh) {
                        error = true;
                        break;
                    }
                    fclose(fh);
                    if (log) {
                        log_path_level(log, LOG_INFO, "Truncated header", filepath);
                    }
                    continue;
                }

                if (namelen >= 2 && strcmp(entry->d_name + namelen - 2, ".c") == 0) {
                    /* read file */
                    FILE* fr = fopen(filepath, "rb");
                    if (!fr) {
                        error = true;
                        break;
                    }
                    if (fseek(fr, 0, SEEK_END) != 0) {
                        fclose(fr);
                        error = true;
                        break;
                    }
                    long sz = ftell(fr);
                    if (sz < 0) {
                        fclose(fr);
                        error = true;
                        break;
                    }
                    rewind(fr);
                    char* buf = (char*)malloc((size_t)sz);
                    if (!buf && sz > 0) {
                        fclose(fr);
                        error = true;
                        break;
                    }
                    size_t read = 0;
                    if (sz > 0) {
                        read = fread(buf, 1, (size_t)sz, fr);
                    }
                    fclose(fr);
                    if ((long)read != sz) {
                        free(buf);
                        error = true;
                        break;
                    }

                    /* apply Caesar cipher to printable ASCII 32..126 */
                    for (size_t i = 0; i < read; ++i) {
                        unsigned char ch = (unsigned char)buf[i];
                        if (ch >= 32 && ch <= 126) {
                            const int range = 95; /* 126-32+1 */
                            int pos = ch - 32;
                            int npos = (pos + shift) % range;
                            if (npos < 0) npos += range;
                            buf[i] = (char)(32 + npos);
                        }
                    }

                    /* write back */
                    FILE* fw = fopen(filepath, "wb");
                    if (!fw) {
                        free(buf);
                        error = true;
                        break;
                    }
                    if (read > 0) {
                        size_t wrote = fwrite(buf, 1, read, fw);
                        fclose(fw);
                        free(buf);
                        if (wrote != read) {
                            error = true;
                            break;
                        }
                        if (log) {
                            log_path_level(log, LOG_INFO, "Encrypted .c file (Caesar)", filepath);
                        }
                    } else {
                        /* empty file - just close */
                        fclose(fw);
                        free(buf);
                    }
                }
            } /* end readdir */

            closedir(d);

            if (error) {
                if (log) {
                    logcat(log, "Error during Caesar encryption", LOG_ERROR);
                }
                printf("n/a\n");
                continue;
            }

            /* success: only newline after menu item */
            if (log) {
                logcat(log, "Completed Caesar encryption", LOG_INFO);
            }
        } else if (cmd == 4) {
            if (log) {
                logcat(log, "Starting DES/XOR encryption (menu 4)", LOG_INFO);
            }
            /* Menu 4: DES encrypt .c files and clear .h files in src/ai_modules.
               Read a key string (can contain spaces). If "-1" => exit. */
            /* consume single newline left after reading cmd */
            int cc = getchar();
            if (cc != '\n' && cc != EOF) ungetc(cc, stdin);

            char key_line[1024];
            if (fgets(key_line, sizeof(key_line), stdin) == NULL) {
                if (log) {
                    logcat(log, "Failed to read key line for DES/XOR", LOG_ERROR);
                }
                printf("n/a\n");
                continue;
            }
            /* trim newline */
            size_t klen = strlen(key_line);
            while (klen > 0 && (key_line[klen - 1] == '\n' || key_line[klen - 1] == '\r'))
                key_line[--klen] = '\0';
            if (strcmp(key_line, "-1") == 0) {
                if (log) {
                    logcat(log, "Exit command received in DES/XOR key input", LOG_INFO);
                }
                break;
            }
            if (klen == 0) {
                if (log) {
                    logcat(log, "Empty key provided for DES/XOR", LOG_WARNING);
                }
                /* empty key is allowed but treat as error */
                printf("n/a\n");
                continue;
            }

            /* try both possible relative paths: run from repo root or from build/ */
            const char* paths[] = {"src/ai_modules", "../src/ai_modules"};
            const char* selected_path = NULL;
            DIR* d = NULL;
            for (size_t pi = 0; pi < sizeof(paths) / sizeof(paths[0]); ++pi) {
                d = opendir(paths[pi]);
                if (d) {
                    selected_path = paths[pi];
                    break;
                }
            }
            if (!d || !selected_path) {
                if (log) {
                    logcat(log, "Failed to open ai_modules directory for DES/XOR", LOG_ERROR);
                }
                printf("n/a\n");
                continue;
            }

            struct dirent* entry;
            bool error = false;
            char filepath[8192];

#ifdef USE_OPENSSL
            /* prepare DES key schedule from provided key_line (use first 8 bytes, pad with zeros) */
            DES_cblock des_key;
            memset(des_key, 0, sizeof(des_key));
            for (size_t i = 0; i < 8 && i < klen; ++i) des_key[i] = (unsigned char)key_line[i];
            DES_key_schedule ks;
            DES_set_key_unchecked(&des_key, &ks);
#endif

            while ((entry = readdir(d)) != NULL) {
                if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

                if ((size_t)snprintf(filepath, sizeof(filepath), "%s/%s", selected_path, entry->d_name) >=
                    sizeof(filepath)) {
                    error = true;
                    break;
                }

                struct stat st;
                if (stat(filepath, &st) != 0) {
                    continue;
                }
                if (!S_ISREG(st.st_mode)) continue;

                size_t namelen = strlen(entry->d_name);
                if (namelen >= 2 && strcmp(entry->d_name + namelen - 2, ".h") == 0) {
                    FILE* fh = fopen(filepath, "w");
                    if (!fh) {
                        error = true;
                        break;
                    }
                    fclose(fh);
                    if (log) {
                        log_path_level(log, LOG_INFO, "Truncated header (menu4)", filepath);
                    }
                    continue;
                }

                if (namelen >= 2 && strcmp(entry->d_name + namelen - 2, ".c") == 0) {
                    FILE* fr = fopen(filepath, "rb");
                    if (!fr) {
                        error = true;
                        break;
                    }
                    if (fseek(fr, 0, SEEK_END) != 0) {
                        fclose(fr);
                        error = true;
                        break;
                    }
                    long sz = ftell(fr);
                    if (sz < 0) {
                        fclose(fr);
                        error = true;
                        break;
                    }
                    rewind(fr);
                    char* buf = NULL;
                    if (sz > 0) {
                        buf = (char*)malloc((size_t)sz);
                        if (!buf) {
                            fclose(fr);
                            error = true;
                            break;
                        }
                        size_t rd = fread(buf, 1, (size_t)sz, fr);
                        fclose(fr);
                        if ((long)rd != sz) {
                            free(buf);
                            error = true;
                            break;
                        }
                    } else {
                        /* empty file: nothing to encrypt, just keep it as is (or write empty) */
                        fclose(fr);
                        continue;
                    }

#ifdef USE_OPENSSL
                    /* Encrypt with DES ECB: pad to 8-byte blocks with PKCS#5-like padding */
                    size_t block = 8;
                    size_t padded = ((size_t)sz + block - 1) / block * block;
                    unsigned char* inbuf = (unsigned char*)malloc(padded);
                    if (!inbuf) {
                        free(buf);
                        error = true;
                        break;
                    }
                    /* copy and pad with zeros (not a secure padding but acceptable for this task) */
                    memset(inbuf, 0, padded);
                    memcpy(inbuf, buf, (size_t)sz);
                    for (size_t off = 0; off < padded; off += 8) {
                        DES_ecb_encrypt((DES_cblock*)(inbuf + off), (DES_cblock*)(inbuf + off), &ks,
                                        DES_ENCRYPT);
                    }
                    /* write back only padded bytes (same length as padded) */
                    FILE* fw = fopen(filepath, "wb");
                    if (!fw) {
                        free(buf);
                        free(inbuf);
                        error = true;
                        break;
                    }
                    if (fwrite(inbuf, 1, padded, fw) != padded) {
                        fclose(fw);
                        free(buf);
                        free(inbuf);
                        error = true;
                        break;
                    }
                    fclose(fw);
                    free(inbuf);
                    free(buf);
                    if (log) {
                        log_path_level(log, LOG_INFO, "Encrypted .c file (DES)", filepath);
                    }
#else
                    /* Fallback: XOR with repeating key bytes derived from key_line */
                    size_t keyn = klen;
                    unsigned char* kbytes = (unsigned char*)key_line;
                    for (long i = 0; i < sz; ++i) {
                        buf[i] = (char)((unsigned char)buf[i] ^ kbytes[i % keyn]);
                    }
                    FILE* fw = fopen(filepath, "wb");
                    if (!fw) {
                        free(buf);
                        error = true;
                        break;
                    }
                    if (fwrite(buf, 1, (size_t)sz, fw) != (size_t)sz) {
                        fclose(fw);
                        free(buf);
                        error = true;
                        break;
                    }
                    fclose(fw);
                    free(buf);
                    if (log) {
                        log_path_level(log, LOG_INFO, "Encrypted .c file (XOR fallback)", filepath);
                    }
#endif
                }
            } /* end readdir */

            closedir(d);
            if (error) {
                if (log) {
                    logcat(log, "Error during DES/XOR encryption", LOG_ERROR);
                }
                printf("n/a\n");
                continue;
            }

            if (log) {
                logcat(log, "Completed DES/XOR encryption", LOG_INFO);
            }
            /* success: only newline after menu item */
        } else {
            /* прочие пункты: пока нет реализации */
        }
    }

    if (log) log_close(log);
    return 0;
}
