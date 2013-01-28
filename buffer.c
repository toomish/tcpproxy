#include "buffer.h"
#include "xwrap.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void binit(struct buffer *b, size_t size)
{
	char *p;

	p = (char *) xmalloc(size);
	b->addr = b->begin = b->end = p;
	b->size = size;
}

void bfree(struct buffer *b)
{
	if (b->addr != NULL) {
		free(b->addr);
		b->addr = b->begin = b->end = NULL;
		b->size = 0;
	}
}

static inline int bavail_write(struct buffer *b)
{
	return b->end - b->begin;
}

static inline int bavail_read(struct buffer *b)
{
	return b->addr + b->size - b->end;
}

static inline void bcheck_empty(struct buffer *b)
{
	if (b->begin == b->end)
		b->begin = b->end = b->addr;
}

int bread(struct buffer *b, int fd)
{
	int size;
	int n;

	size = bavail_read(b);
	if (size == 0)
		return 0;

	n = read(fd, b->end, size);
	if (n < 1)
		return -1;
	b->end += n;
	return n;
}

int bwrite(struct buffer *b, int fd)
{
	int size;
	int n;

	size = bavail_write(b);
	if (size == 0)
		return 0;
	
	n = write(fd, b->begin, size);
	if (n < 1)
		return -1;

	b->begin += n;
	bcheck_empty(b);

	return n;
}

int bgets(struct buffer *b, char *s, size_t len)
{
	int size;
	char *p;
	int n;

	if (len == 0)
		return 0;

	size = bavail_write(b);
	if (size == 0)
		return 0;

	if ((p = memchr(b->begin, '\n', size)) == NULL)
		return 0;

	n = p - b->begin + 1;
	if (len > n)
		len = n;

	memcpy(s, b->begin, len);
	b->begin += len;
	bcheck_empty(b);

	return len;
}

int bputs(struct buffer *b, char *s, size_t len)
{
	int size;

	if (len == 0)
		return 0;

	size = bavail_read(b);
	if (size == 0)
		return 0;

	if (len > size)
		len = size;

	memcpy(b->end, s, len);
	b->end += len;

	return len;
}

int bcanfill(struct buffer *b)
{
	return bavail_read(b) > 0;
}

int bhasdata(struct buffer *b)
{
	return bavail_write(b) > 0;
}

