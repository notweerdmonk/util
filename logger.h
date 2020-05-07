
#ifndef LOGGER_H
#define LOGGER_H

#define _POSIX_SOURCE

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#define ANSI_FG_BLACK   "\x1b[30m"
#define ANSI_FG_RED     "\x1b[31m"
#define ANSI_FG_GREEN   "\x1b[32m"
#define ANSI_FG_YELLOW  "\x1b[33m"
#define ANSI_FG_BLUE    "\x1b[34m"
#define ANSI_FG_MAGENTA "\x1b[35m"
#define ANSI_FG_CYAN    "\x1b[36m"
#define ANSI_FG_WHITE   "\x1b[37m"

#define ANSI_BG_BLACK   "\x1b[40m"
#define ANSI_BG_RED     "\x1b[41m"
#define ANSI_BG_GREEN   "\x1b[42m"
#define ANSI_BG_YELLOW  "\x1b[43m"
#define ANSI_BG_BLUE    "\x1b[44m"
#define ANSI_BG_MAGENTA "\x1b[45m"
#define ANSI_BG_CYAN    "\x1b[46m"
#define ANSI_BG_WHITE   "\x1b[47m"

#define ANSI_FG_RESET   "\x1b[0m"
#define ANSI_BG_RESET   "\x1b[49m"

#define LOG_BUFFER_SIZE 512

#if defined _POSIX_SOURCE
extern FILE *fdopen(int fd, const char *mode);
#endif

enum logger_level {
  LOGGER_ALL = -1,
  LOGGER_DEBUG,
  LOGGER_INFO,
  LOGGER_WARNING,
  LOGGER_ERROR,
  LOGGER_CRITICAL
};

typedef void (*log_function_ptr)(const char *msg);

struct logger {
  enum logger_level level;
  log_function_ptr pfunction;
};

struct file_logger {
  struct logger log;
  FILE *f;
};

static const
char *__logger_level_strings[] =  {
  ANSI_FG_BLUE   ANSI_BG_RESET "DEBUG"    ANSI_FG_RESET,
  ANSI_FG_GREEN  ANSI_BG_RESET "INFO"     ANSI_FG_RESET,
  ANSI_FG_YELLOW ANSI_BG_RESET "WARNING"  ANSI_FG_RESET,
  ANSI_FG_RED    ANSI_BG_RESET "ERROR"    ANSI_FG_RESET,
  ANSI_FG_WHITE  ANSI_BG_RED   "CRITICAL" ANSI_FG_RESET };

static char __log_buffer[LOG_BUFFER_SIZE];
static FILE *__file_ptr;

#define LOG(plog, level, ...) \
  do { \
    if (plog) \
      logger_log((struct logger*)plog, level, __LINE__, __FILE__, __VA_ARGS__); \
  } while(0)


static
void logger_set_level(struct logger *plogger, enum logger_level level) {
  plogger->level = level;
}

static
void logger_set_function(struct logger *plogger, log_function_ptr pfunction) {
  plogger->pfunction = pfunction;
}

static
void logger_log(struct logger *plogger, enum logger_level loglevel, int linenum,
  const char *filename, const char *msg, ...) {
  if (loglevel >= plogger->level) {
    va_list args; va_start(args, msg);
    time_t t = time(NULL); struct tm tm = *localtime(&t);
    int len = sprintf(__log_buffer,
                      "%02d-%02d-%04d : %02d:%02d:%02d : %s:%05d : %8s : ",
                      tm.tm_mon + 1, tm.tm_mday, tm.tm_year + 1900,
                      tm.tm_hour, tm.tm_min, tm.tm_sec,
                      filename, linenum, __logger_level_strings[loglevel]);
    vsprintf(__log_buffer + len, msg, args);
    va_end(args);
    plogger->pfunction(__log_buffer);
  }
}

static
void file_logger(const char *msg) {
  fputs(msg, __file_ptr); fputs("\n", __file_ptr);
}

static
void logger_set_file(struct file_logger *flog, const char *file) {
  if (flog && file) {
    FILE *f = 0;
    int fd = open(file, O_WRONLY|O_CREAT|O_APPEND|O_SYNC, \
      S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH);
    if (fd) {
      f = fdopen(fd, "w");
      if (!f) {
        fprintf(stderr, "%s:%d: fdopen failed: %s\n", __func__, __LINE__,
          strerror(errno));
        close(fd);
      }
    } else {
      fprintf(stderr, "%s:%d: open failed: %s\n", __func__, __LINE__,
        strerror(errno));
    }
    __file_ptr = f;
    logger_set_function(&flog->log, file_logger);
  }
}

static
void logger_unset_file(struct file_logger *flog) {
  if (flog && flog->f)
    fclose(flog->f), flog->f = 0;
}

#endif /* LOGGER_H */
