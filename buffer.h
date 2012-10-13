#ifndef BUFFER_H
#define BUFFER_H

#include <sys/types.h>

struct buffer {
	char *addr;
	char *begin;
	char *end;
	int size;
};

void binit(struct buffer *b, size_t size);
void bfree(struct buffer *b);
int bread(struct buffer *b, int fd);
int bwrite(struct buffer *b, int fd);
int bcanfill(struct buffer *b);
int bhasdata(struct buffer *b);

#endif
