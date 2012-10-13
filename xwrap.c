#include <string.h>
#include <stdlib.h>

#include "debug.h"

void *xmalloc(size_t size)
{
	void *p;

	p = malloc(size);
	if (p == NULL)
		sys_err("malloc %zd bytes", size);
	return p;
}

char *xstrdup(const char *s)
{
	int len;

	len = strlen(s) + 1;
	return memcpy(xmalloc(len), s, len);
}

