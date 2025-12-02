#include "logger.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char* level_names[] = {"DEBUG", "TRACE", "INFO", "WARNING", "ERROR"};

FILE* log_init(char* filename) {
    if (!filename) return NULL;
    /* open in "w" mode to truncate existing log on start */
    FILE* f = fopen(filename, "w");
    return f;
}

int logcat(FILE* log_file, char* message, enum log_level level) {
    if (!log_file || !message) return -1;
    const char* lname = "UNKNOWN";
    if ((int)level >= 0 && (int)level < (int)(sizeof(level_names) / sizeof(level_names[0]))) {
        lname = level_names[level];
    }
    time_t t = time(NULL);
    struct tm tm;
#if defined(_WIN32) || defined(_WIN64)
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    char timestr[64];
    if (strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", &tm) == 0) {
        strcpy(timestr, "0000-00-00 00:00:00");
    }
    if (fprintf(log_file, "[%s] %s %s\n", lname, timestr, message) < 0) return -1;
    fflush(log_file);
    return 0;
}

int log_close(FILE* log_file) {
    if (!log_file) return -1;
    if (fclose(log_file) != 0) return -1;
    return 0;
}
