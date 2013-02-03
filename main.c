#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/queue.h>
#include <sys/wait.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdbool.h>
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>

#include "buffer.h"
#include "debug.h"
#include "xwrap.h"

#define LIST_FOREACH_SAFE(var, tmp, head, field) \
	for (	(var) = LIST_FIRST(head), (tmp) = LIST_NEXT(var, field); \
		(var); \
		(var) = (tmp), (tmp) = (var) ? LIST_NEXT(var, field) : NULL)

#define NELEM(p) (sizeof(p) / sizeof(p[0]))
#define BUFSIZE 0x1000
#define CMDLEN 32

#define bputconst(b, s) bputs(b, s, sizeof(s) - 1)

typedef enum {
	UNIX,
	TCP
} socket_type_t;

LIST_HEAD(channel_list, channel) channels;
SLIST_HEAD(server_list, server) servers;

static char *option_unix_socket_path;
static char *option_config_path;

struct server {
	int sock;
	int local_port;
	char *remote_addr;
	socket_type_t type;
	struct sockaddr_storage remote_sa;
	int nchannel;

	SLIST_ENTRY(server) entries;
};

struct channel {
	struct buffer buf1;
	struct buffer buf2;
	int fd1;		/* client socket */
	int fd2;		/* remote socket */
	int connected;
	char *addr;
	struct server *server;
	char control;
	char control_shutdown;

	LIST_ENTRY(channel) entries;
};

struct command {
	char *name;
	int (*handler)(char **args, struct buffer *out);
};

static int cmd_echo(char **args, struct buffer *out);
static int cmd_list(char **args, struct buffer *out);
static int cmd_quit(char **args, struct buffer *out);
static int cmd_bye(char **args, struct buffer *out);

struct command commands[] = {
	{ "echo", cmd_echo },
	{ "list", cmd_list },
	{ "quit", cmd_quit },
	{ "exit", cmd_quit },
	{ "bye", cmd_bye },
	{ NULL, NULL }
};

static inline int max(int a, int b)
{
	return a > b ? a : b;
}

static inline int tcp_socket(void);
static int tcp_server(struct sockaddr *sa, socklen_t addrlen);
static inline int unix_socket(void);
static int unix_server(const char *name);
static void set_nonblock(int desc);
static inline void shut(int *fd);

static void usage(void);
static void sighandler(int signum);
static void init_handlers(void);
static int isnumber(const char *str);
static void on_quit(void);

static bool makeaddr(struct sockaddr_in *sa, const char *host, const char *port);
static int portbyname(const char *name);
static char *addrstr(struct sockaddr_storage *ss);

static struct channel *chan_new(struct server *s, char *addr, int fd1, int fd2);
static void chan_free(struct channel *chan);

static bool server_add_tcp(char *local_port, char *host, char *port);
static bool server_add_unix(char *local_port, char *path);
static bool server_add_new(char *local_port, socket_type_t type, struct sockaddr_storage *ss);

static void endless_loop(int unix_sock);

static void read_config_file(char *name)
{
	static char *delim = " \r\t\n";

	char *line = NULL;
	size_t len = 0;
	int nline = 0;
	FILE *fp;

	if ((fp = fopen(name, "r")) == NULL)
		sys_err("fopen %s", name);

	while (getline(&line, &len, fp) >= 0) {
		char *local, *type;

		nline++;

		if ((local = strtok(line, delim)) == NULL)
			goto invalid;

		if (*local == '#')
			continue;

		if ((type = strtok(NULL, delim)) == NULL)
			goto invalid;

		if (! strcmp(type, "unix")) {
			char *path = strtok(NULL, delim);

			if (path == NULL)
				goto invalid;

			if (! server_add_unix(local, path))
				goto invalid;
		} else {
			char *host, *port = NULL;

			if (! strcmp(type, "tcp"))
				host = strtok(NULL, delim);
			else
				host = type;

			if (host != NULL)
				port = strtok(NULL, delim);

			if (port == NULL)
				goto invalid;

			if (! server_add_tcp(local, host, port))
				goto invalid;
		}
	}

	fclose(fp);
	free(line);
	return;

invalid:
	err_quit("%s: invalid line %d", name, nline);
}

static void usage(void)
{
	fprintf(stderr, "Usage:\n  %s [OPTION...]\n", PROGNAME);
	fprintf(stderr, "\nHelp Options:\n");
	fprintf(stderr, "  %-40sShow help options\n", "-h, --help");
	fprintf(stderr, "\nApplication Options:\n");
	fprintf(stderr, "  %-40sconfig file\n", "-c, --config");
	fprintf(stderr, "  %-40sunix socket path\n\n", "-u, --unix");
}

static int parse_options(int argc, char **argv)
{
	static struct option options[] = {
		{ "config", 1, NULL, 'c' },
		{ "unix", 1, NULL, 'u' },
		{ "help", 0, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	int opt;

	while ((opt = getopt_long(argc, argv, "c:u:h", options, NULL)) != -1) {
		switch (opt) {
		case 'c':
			option_config_path = xstrdup(optarg);
			break;
		case 'u':
			option_unix_socket_path = xstrdup(optarg);
			break;
		case 'h':
			usage();
		default:
			return -1;
		}
	}

	if (option_config_path == NULL) {
		fprintf(stderr, "config option missed\n");
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int unix_sock = -1;

	if (parse_options(argc, argv) < 0)
		exit(EXIT_FAILURE);

	if (option_unix_socket_path != NULL)
		unix_sock = unix_server(option_unix_socket_path);

	atexit(on_quit);

	SLIST_INIT(&servers);

	setservent(1);
	read_config_file(option_config_path);
	endservent();

	LIST_INIT(&channels);
	init_handlers();
	endless_loop(unix_sock);

	return 0;
}

static void init_handlers(void)
{
	struct sigaction act;
	int sigs[] = { SIGINT, SIGTERM };
	int n;

	memset(&act, 0, sizeof(act));
	act.sa_handler = sighandler;
	act.sa_flags = SA_RESTART;

	for (n = 0; n < NELEM(sigs); n++)
		if (sigaction(sigs[n], &act, NULL) < 0)
			sys_err("sigaction");
}

static void sighandler(int signum)
{
	exit(0);
}

static struct channel *chan_new(struct server *s, char *addr, int fd1, int fd2)
{
	struct channel *p;

	p = (struct channel *) xmalloc(sizeof(*p));
	binit(&p->buf1, BUFSIZE);
	binit(&p->buf2, BUFSIZE);
	p->fd1 = fd1;
	p->fd2 = fd2;
	p->addr = addr;
	p->connected = 0;
	p->server = s;
	p->control = 0;
	p->control_shutdown = 0;

	LIST_INSERT_HEAD(&channels, p, entries);

	if (s != NULL)
		s->nchannel++;

	return p;
}

static void chan_free(struct channel *chan)
{
	struct server *s = chan->server;

	bfree(&chan->buf1);
	bfree(&chan->buf2);

	if (chan->fd1 >= 0)
		shut(&chan->fd1);
	if (chan->fd2 >= 0)
		shut(&chan->fd2);

	free(chan->addr);
	LIST_REMOVE(chan, entries);
	free(chan);

	if (s != NULL)
		s->nchannel--;
}

static bool server_add_tcp(char *local_port, char *host, char *port)
{
	struct sockaddr_storage storage;

	memset(&storage, 0, sizeof(storage));
	if (! makeaddr((struct sockaddr_in *) &storage, host, port))
		return false;

	return server_add_new(local_port, TCP, &storage);
}

static bool server_add_unix(char *local_port, char *path)
{
	union {
		struct sockaddr_storage storage;
		struct sockaddr_un un;
	} sa;

	memset(&sa, 0, sizeof(sa));
	sa.un.sun_family = AF_UNIX;
	strcpy(sa.un.sun_path, path);

	return server_add_new(local_port, UNIX, &sa.storage);
}

static bool server_add_new(char *local_port, socket_type_t type, struct sockaddr_storage *ss)
{
	struct sockaddr_in sa;
	struct server *s;
	int sock;

	if (! makeaddr(&sa, "0.0.0.0", local_port))
		return false;

	sock = tcp_server((struct sockaddr *) &sa, sizeof(sa));
	if (sock < 0)
		return false;

	s = (struct server *) xmalloc(sizeof(*s));
	s->nchannel = 0;

	s->type = type;
	memcpy(&s->remote_sa, ss, sizeof(struct sockaddr_storage));
	s->remote_addr = addrstr(&s->remote_sa);

	s->local_port = ntohs(sa.sin_port);
	s->sock = sock;

	SLIST_INSERT_HEAD(&servers, s, entries);

	return true;
}

static inline int tcp_socket(void)
{
	int sock;

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		msg_err("socket");
		return -1;
	}

	set_nonblock(sock);

	return sock;
}

static void on_quit(void)
{
	char *path = option_unix_socket_path;

	if (path != NULL) {
		if (path[0] != '\0' && unlink(path) < 0)
			sys_err("unlink");
	}
}

static int isnumber(const char *str)
{
	const char *p;

	for (p = str; *p != '\0'; p++)
		if (isdigit(*p) == 0)
			return 0;

	return 1;
}

static int portbyname(const char *name)
{
	struct servent *se;

	if (isnumber(name))
		return htons(atoi(name));

	se = getservbyname(name, "tcp");
	if (se == NULL) {
		msg_warn("unknown service %s", name);
		return -1;
	}

	return se->s_port;
}

static bool makeaddr(struct sockaddr_in *sa, const char *host, const char *port)
{
	int tmp;

	if ((tmp = portbyname(port)) < 0)
		return false;

	memset(sa, 0, sizeof(*sa));
	if (inet_aton(host, &sa->sin_addr) == 0) {
		msg_warn("inet_aton %s failed", host);
		return false;
	}

	sa->sin_family = AF_INET;
	sa->sin_port = tmp;

	return true;
}

static char *addrstr(struct sockaddr_storage *ss)
{
	char buf[512];

	switch (ss->ss_family) {
	case AF_UNIX: {
		struct sockaddr_un *sa = (struct sockaddr_un *) ss;
		strcpy(buf, sa->sun_path);
	}	break;
	case AF_INET: {
		struct sockaddr_in *sa = (struct sockaddr_in *) ss;
		snprintf(buf, sizeof(buf), "%s:%d",
			inet_ntoa(sa->sin_addr), ntohs(sa->sin_port));
	} 	break;
	default:
		strcpy(buf, "unknown");
	}

	return xstrdup(buf);
}

static inline void shut(int *fd)
{
	shutdown(*fd, SHUT_RDWR);
	close(*fd);
	*fd = -1;
}

static int tcp_server(struct sockaddr *sa, socklen_t addrlen)
{
	int flag;
	int sock;

	if ((sock = tcp_socket()) < 0)
		return -1;

	flag = 1;

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0) {
		msg_err("setsockopt SO_REUSEADDR failed");
		goto fail;
	}

	if (bind(sock, sa, addrlen) < 0) {
		msg_err("bind");
		goto fail;
	}

	if (listen(sock, 7) < 0) {
		msg_err("listen");
		goto fail;
	}

	return sock;

fail:
	close(sock);
	return -1;
}

static inline int unix_socket(void)
{
	int sock;

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		msg_err("socket PF_UNIX");
		return -1;
	}

	set_nonblock(sock);

	return sock;
}

static int unix_server(const char *name)
{
	struct sockaddr_un sa;
	int sock;

	sock = unix_socket();
	memset(&sa, 0, sizeof(sa));
	sa.sun_family = PF_UNIX;
	strcpy(sa.sun_path, name);
	if (bind(sock, (struct sockaddr *) &sa, sizeof(sa)) < 0)
		sys_err("unix_server: bind failed");
	if (listen(sock, 7) < 0)
		sys_err("unix_server: listen failed");

	return sock;
}
	
static void set_nonblock(int desc)
{
	int opts;

	opts = fcntl(desc, F_GETFL);
	if (opts < 0)
		msg_err("fcntl");
	else {
		opts |= O_NONBLOCK;
		if (fcntl(desc, F_SETFL, opts) < 0)
			msg_err("fcntl");
	}
}

static int add_chans(fd_set *readfds, fd_set *writefds, fd_set *exceptfds)
{
	struct channel *chan;
	struct buffer *b1, *b2;
	int fd1, fd2;
	int nfds = -1;

	LIST_FOREACH(chan, &channels, entries) {
		b1 = &chan->buf1;
		b2 = &chan->buf2;
		fd1 = chan->fd1;
		fd2 = chan->fd2;

		if (chan->connected == 0) {
			FD_SET(fd2, writefds);
			nfds = max(nfds, fd2);
			continue;
		}

		if (fd1 >= 0) {
			if (bcanfill(b1))
				FD_SET(fd1, readfds);
			if (bhasdata(b2))
				FD_SET(fd1, writefds);

			FD_SET(fd1, exceptfds);
			nfds = max(nfds, fd1);
		}

		if (fd2 >= 0) {
			if (bcanfill(b2))
				FD_SET(fd2, readfds);
			if (bhasdata(b1))
				FD_SET(fd2, writefds);

			FD_SET(fd2, exceptfds);
			nfds = max(nfds, fd2);
		}
	}

	return nfds;
}

static int add_servs(fd_set *readfds)
{
	struct server *server;
	int nfds = -1;

	SLIST_FOREACH(server, &servers, entries) {
		int fd = server->sock;

		FD_SET(fd, readfds);
		nfds = max(nfds, fd);
	}

	return nfds;
}

static inline int connected(int sock)
{
	int optval;
	socklen_t optlen;
	int ret;

	optlen = sizeof(optval);
	ret = getsockopt(sock, SOL_SOCKET, SO_ERROR, (void *) &optval, &optlen);
	if (ret < 0)
		sys_err("getsockopt");
	if (optval == 0)
		return 0;

	errno = optval;
	return -1;
}

static int cmd_list_conn(struct buffer *out)
{
	struct channel *chan;
	char buf[512];
	int total = 0;
	int n;

	LIST_FOREACH(chan, &channels, entries) {
		if (chan->control)
			bputconst(out, "[control]\n");
		else {
			n = snprintf(buf, sizeof(buf), "%s => %s%s\n",
				chan->addr, chan->server->remote_addr,
				chan->connected ? "" : ": not connected"
			);
			if (n < 0) {
				bputconst(out, "internal error\n");
				return 0;
			}

			bputs(out, buf, n);
		}

		total++;
	}

	if ((n = snprintf(buf, sizeof(buf), "total: %d\n", total)) < 0) {
		bputconst(out, "internal error\n");
		return 0;
	}

	bputs(out, buf, n);

	return 1;
}

static int cmd_list_servers(struct buffer *out)
{
	struct server *serv;
	char buf[512];
	int n;

	SLIST_FOREACH(serv, &servers, entries) {
		n = snprintf(buf, sizeof(buf), "%d => %s: %d\n",
			serv->local_port, serv->remote_addr, serv->nchannel
		);
		if (n < 0) {
			bputconst(out, "internal error\n");
			return 0;
		}

		bputs(out, buf, n);
	}

	return 1;
}

static int cmd_list(char **args, struct buffer *out)
{
	if (args[1] == NULL)
		return cmd_list_conn(out);

	if (! strcmp(args[1], "conn"))
		return cmd_list_conn(out);

	if (! strcmp(args[1], "servers"))
		return cmd_list_servers(out);

	bputconst(out, "unknown arg\n");
	return 1;
}

static int cmd_quit(char **args, struct buffer *out)
{
	(void) args;
	bputconst(out, "bye\n");
	return 0;
}

static int cmd_bye(char **args, struct buffer *out)
{
	(void) args;
	(void) out;
	return 0;
}

static int cmd_echo(char **args, struct buffer *out)
{
	char **p = args + 1;

	if (*p != NULL)
		bputs(out, *p, strlen(*p));

	for (p++; *p != NULL; p++) {
		bputs(out, " ", 1);
		bputs(out, *p, strlen(*p));
	}

	bputs(out, "\n", 1);

	return 1;
}

static void parse_args(char *buf, char **args, int nargs)
{
	char *s;

	s = *args++ = buf;

	for (nargs--; nargs > 0; nargs--) {
		s = strchr(s, ' ');
		if (s == NULL)
			break;

		*s = '\0';
		while (*++s == ' ');

		if (*s == '\0')
			break;

		*args++ = s;
	}
}

static int control_process(struct buffer *in, struct buffer *out)
{
	struct command *cmd;
	char buf[CMDLEN];
	char *args[16] = { 0 };
	int n;

	while ((n = bgets(in, buf, sizeof(buf))) > 0) {
		if (buf[n - 1] != '\n') {
			bputconst(out, "command too long\n");
			return 0;
		}

		if (n == 1)
			continue;

		buf[n - 1] = '\0';
		parse_args(buf, args, NELEM(args) - 1);

		for (cmd = commands; cmd->name != NULL; cmd++) {
			if (! strcmp(buf, cmd->name)) {
				if (! cmd->handler(args, out))
					return 0;

				break;
			}
		}

		if (cmd->name == NULL)
			bputconst(out, "unknown command\n");
	}

	return 1;
}

static void test_chans(fd_set *readfds, fd_set *writefds, fd_set *exceptfds)
{
	struct channel *chan, *tmp;
	struct buffer *b1, *b2;
	int fd1, fd2;
	int n;

	LIST_FOREACH_SAFE(chan, tmp, &channels, entries) {
		b1 = &chan->buf1;
		b2 = &chan->buf2;
		fd1 = chan->fd1;
		fd2 = chan->fd2;

		if (chan->connected == 0) {
			if (FD_ISSET(fd2, writefds) == 0)
				;
			else if (connected(fd2) < 0) {
				msg_err("connect");
				chan_free(chan);
			} else
				chan->connected = 1;

			continue;
		}

		if (fd1 >= 0 && FD_ISSET(fd1, exceptfds)) {
			char ch;

			ch = recv(fd1, &ch, 1, MSG_OOB);
			if (ch < 0)
				shut(&fd1);
			else
				send(fd1, &ch, 1, MSG_OOB);
		}

		if (fd1 >= 0 && FD_ISSET(fd1, readfds)) {
			if ((n = bread(b1, fd1)) < 0)
				shut(&fd1);
			else {
				DEBUG_CODE(
					msg_warn("read from %s %d bytes",
						chan->addr, n);
				);

				if (chan->control) {
					if (! control_process(b1, b2))
						chan->control_shutdown = 1;
				}
			}
		}

		if (fd1 >= 0 && FD_ISSET(fd1, writefds)) {
			if ((n = bwrite(b2, fd1)) < 0)
				shut(&fd2);
			else
				DEBUG_CODE(
					msg_warn("write to %s %d bytes",
						chan->addr, n);
				);
		}

		if (fd2 >= 0 && FD_ISSET(fd2, exceptfds)) {
			char ch;

			ch = recv(fd2, &ch, 1, MSG_OOB);
			if (ch < 1)
				shut(&fd2);
			else
				send(fd2, &ch, 1, MSG_OOB);
		}

		if (fd2 >= 0 && FD_ISSET(fd2, readfds)) {
			if ((n = bread(b2, fd2)) < 0)
				shut(&fd2);
			else
				DEBUG_CODE(
					msg_warn("read from %s %d bytes",
						chan->server->remote_addr, n);
				);
		}

		if (fd2 >= 0 && FD_ISSET(fd2, writefds)) {
			if ((n = bwrite(b1, fd2)) < 0)
				shut(&fd2);
			else
				DEBUG_CODE(
					msg_warn("write to %s %d bytes",
						chan->server->remote_addr, n);
				);
		}

		if (! chan->control || chan->control_shutdown) {
			if (fd1 >= 0 && fd2 < 0 && bhasdata(b2) == 0)
				shut(&fd1);
			if (fd2 >= 0 && fd1 < 0 && bhasdata(b1) == 0)
				shut(&fd2);
		}

		chan->fd1 = fd1;
		chan->fd2 = fd2;

		if (fd1 < 0 && fd2 < 0) {
			if (chan->control)
				fprintf(stderr, "close unix\n");
			else
				fprintf(stderr, "close: %s to %s\n", chan->addr,
					chan->server->remote_addr);
			chan_free(chan);
		}
	}
}

static void accept_client(struct server *server, int serv_sock)
{
	struct channel *chan;
	struct sockaddr_storage ss;
	socklen_t salen, addrlen = 0;
	int fd1, fd2 = -1;
	int ret;

	salen = sizeof(ss);
	fd1 = accept(serv_sock, (struct sockaddr *) &ss, &salen);
	if (fd1 < 0) {
		if (errno != EAGAIN)
			msg_err("accept");
		return;
	}

	if (server->type == TCP) {
		fd2 = tcp_socket();
		addrlen = sizeof(struct sockaddr_in);
	} else if (server->type == UNIX) {
		fd2 = unix_socket();
		addrlen = sizeof(struct sockaddr_un);
	}

	if (fd2 < 0) {
		close(fd1);
		return;
	}

	ret = connect(fd2, (struct sockaddr *) &server->remote_sa, addrlen);
	if (ret < 0 && errno != EINPROGRESS) {
		close(fd1);
		close(fd2);

		msg_err("connect");
		return;
	}

	chan = chan_new(server, addrstr(&ss), fd1, fd2);
	if (ret == 0)
		chan->connected++;

	fprintf(stderr, "accept: %s to %s\n", chan->addr, server->remote_addr);
}

static int test_servs(fd_set *readfds)
{
	struct server *server;
	int count = 0;

	SLIST_FOREACH(server, &servers, entries) {
		int fd = server->sock;

		if (FD_ISSET(fd, readfds)) {
			accept_client(server, fd);
			count++;
		}
	}

	return count;
}

static void accept_unix(int unix_sock)
{
	struct channel *chan;
	int sock;

	sock = accept(unix_sock, NULL, NULL);
	if (sock < 0) {
		if (errno != EAGAIN)
			msg_err("accept");
		return;
	}

	chan = chan_new(NULL, NULL, sock, -1);
	chan->connected = 1;
	chan->control = 1;

	fprintf(stderr, "accept unix\n");
}

static void endless_loop(int unix_sock)
{
	fd_set init_rd;
	int init_nfds = -1;

	FD_ZERO(&init_rd);
	if (unix_sock >= 0) {
		FD_SET(unix_sock, &init_rd);
		init_nfds = unix_sock;
	}

	init_nfds = max(add_servs(&init_rd), init_nfds);

	for (;;) {
		fd_set rd, wr, er;
		int nfds, ret;

		memcpy(&rd, &init_rd, sizeof(fd_set));
		FD_ZERO(&wr);
		FD_ZERO(&er);

		nfds = max(add_chans(&rd, &wr, &er), init_nfds);

		if (nfds < 0)
			break;

		ret = select(nfds + 1, &rd, &wr, &er, NULL);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			sys_err("select");
		}

		ret -= test_servs(&rd);

		if (unix_sock >= 0) {
			if (ret > 0 && FD_ISSET(unix_sock, &rd)) {
				accept_unix(unix_sock);
				ret--;
			}
		}

		if (ret > 0)
			test_chans(&rd, &wr, &er);
	}
}

