#include <sys/socket.h>
#include <sys/un.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "debug.h"
#include "data.h"

static char buf[0x1000];

int main(int argc, char *argv[])
{
	struct sockaddr_un sa;
	int sock;
	int n;

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		sys_err("socket");

	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	strcpy(sa.sun_path, UNIX_SOCKET_PATH);
	if (connect(sock, (struct sockaddr *) &sa, sizeof(sa)) < 0)
		sys_err("connect");

	while ((n = read(sock, buf, sizeof(buf))) > 0) {
		buf[n] = 0;
		fputs(buf, stdout);
	}

	if (n < 0)
		sys_err("read");

	close(sock);
	return 0;
}

