#include <sys/socket.h>
#include <sys/un.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "debug.h"

#define COMMAND "list\nbye\n"

static char buf[0x1000];

int main(int argc, char *argv[])
{
	struct sockaddr_un sa;
	int sock;
	int n;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s socket_path\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		sys_err("socket");

	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	strcpy(sa.sun_path, argv[1]);
	if (connect(sock, (struct sockaddr *) &sa, sizeof(sa)) < 0)
		sys_err("connect");

	if (write(sock, COMMAND, sizeof(COMMAND) - 1) < 0)
		sys_err("write");

	while ((n = read(sock, buf, sizeof(buf))) > 0) {
		buf[n] = 0;
		fputs(buf, stdout);
	}

	if (n < 0)
		sys_err("read");

	close(sock);
	return 0;
}

