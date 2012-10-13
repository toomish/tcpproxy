#ifndef XWRAP_H
#define XWRAP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

void *xmalloc(size_t size);
char *xstrdup(const char *s);

#ifdef __cplusplus
}
#endif

#endif
