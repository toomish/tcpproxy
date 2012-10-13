#include "buffer.h"
#include "xwrap.h"

#include <stdlib.h>
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
	if (b->begin == b->end)
		b->begin = b->end = b->addr;
	return n;
}

int bcanfill(struct buffer *b)
{
	return bavail_read(b) > 0;
}

int bhasdata(struct buffer *b)
{
	return bavail_write(b) > 0;
}

