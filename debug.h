#ifndef __DEBUG_H
#define __DEBUG_H

#include <stdio.h>
#include <errno.h>

#ifndef NOCOLOR
#define GREEN	"[32m"
#define DEF	"[0m"
#define RED 	"[31m"
#else
#define GREEN
#define DEF
#define RED
#endif

#ifndef NDEBUG
#define DEBUG_CODE(code) \
do { \
	code; \
} while (0)
#else
#define DEBUG_CODE(code)
#endif

#define PROMPT_FMT(fmt) GREEN "%s" DEF ":" GREEN "%d" DEF ": " fmt

#define msg_err(fmt, args...) \
	fprintf(stderr, PROMPT_FMT(fmt) ": " \
		RED "%s" DEF "\n", \
		__FILE__, __LINE__, ## args, strerror(errno))

#define msg_warn(fmt, args...) \
	fprintf(stderr, PROMPT_FMT(fmt) "\n", \
		__FILE__, __LINE__, ## args)

#define sys_err(fmt, args...) \
do { \
	msg_err(fmt, ## args); \
	exit(1); \
} while (0)

#define err_quit(fmt, args...) \
do { \
	msg_warn(fmt, ## args); \
 	exit(1); \
} while (0)

#endif
