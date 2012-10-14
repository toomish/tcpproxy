#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

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
#include "list.h"
#include "data.h"

#define NELEM(p) (sizeof(p) / sizeof(p[0]))
#define BUFSIZE 0x1000

static struct list_head channels;
static struct list_head servers;
static int die_childs;
static pid_t main_pid;

struct server {
	int sock;
	char *remote_addr;
	struct sockaddr_in remote_sa;
	int nchannel;
	struct list_head serv_list;
};

struct channel {
	struct buffer buf1;
	struct buffer buf2;
	int fd1;		/* client socket */
	int fd2;		/* remote socket */
	int connected;
	char *addr;
	struct server *server;
	struct list_head chan_list;
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
static void wait_childs(void);
static int isnumber(const char *str);
static void on_quit(void);

static void makeaddr(struct sockaddr_in *sa, const char *host, const char *port);
static int portbyname(const char *name);
static char *addrstr(struct sockaddr_in *sa);

static struct channel *chan_new(struct server *s, char *addr, int fd1, int fd2);
static void chan_free(struct channel *chan);

static void serv_add_new(char *local_port, char *host, char *port);

static void endless_loop(int unix_sock);

static void read_config_file(char *name)
{
	static char *delim = " \r\t\n";

	char *line = NULL;
	size_t len = 0;
	int nline = 1;
	FILE *fp;

	if ((fp = fopen(name, "r")) == NULL)
		sys_err("fopen %s", name);

	while (getline(&line, &len, fp) >= 0) {
		char *local, *host, *port;

		local = host = port = NULL;

		if ((local = strtok(line, delim)) != NULL) {
			if ((host = strtok(NULL, delim)) != NULL)
				port = strtok(NULL, delim);
		}

		if (port == NULL)
			err_quit("%s: invalid line %d", name, nline);

		serv_add_new(local, host, port);
		nline++;
	}

	fclose(fp);
	free(line);
}

int main(int argc, char *argv[])
{
	int unix_sock;

	if (argc < 2)
		usage();

	unix_sock = unix_server(UNIX_SOCKET_PATH);

	main_pid = getpid();
	atexit(on_quit);

	INIT_LIST_HEAD(&servers);

	setservent(1);
	read_config_file(argv[1]);
	endservent();

	INIT_LIST_HEAD(&channels);
	init_handlers();
	endless_loop(unix_sock);

	return 0;
}

static inline void xsigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
	int ret;

	ret = sigprocmask(how, set, oldset);
	if (ret < 0)
		sys_err("sigprocmask");
}

static inline void xsigpending(sigset_t *set)
{
	if (sigpending(set) < 0)
		sys_err("sigpending");
}

static void init_handlers(void)
{
	struct sigaction act;
	int sigs[] = { SIGINT, SIGTERM };
	int n;

	memset(&act, 0, sizeof(act));
	act.sa_handler = sighandler;
	act.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &act, NULL) < 0)
		sys_err("sigaction");
	if (siginterrupt(SIGCHLD, 1) < 0)
		sys_err("siginterrupt");

	for (n = 0; n < NELEM(sigs); n++)
		if (sigaction(sigs[n], &act, NULL) < 0)
			sys_err("sigaction");
}

static void sighandler(int signum)
{
	if (signum == SIGCHLD)
		die_childs++;
	else
		exit(0);
}

static void wait_childs(void)
{
	int status;
	pid_t pid;

	for (;;) {
		pid = waitpid(-1, &status, WNOHANG);
		if (pid == 0)
			goto out;
		else if (pid == -1)
			switch (errno) {
			case ECHILD:
				goto out;
			case EINTR:
				continue;
			default:
				sys_err("waitpid");
			}

		DEBUG_CODE(
			fprintf(stderr, "child %d ", pid);
			if (WIFEXITED(status))
				fprintf(stderr, "exited with status %d\n",
					WEXITSTATUS(status));
			else if (WIFSIGNALED(status))
				fprintf(stderr, "caught signal %d\n",
					WTERMSIG(status));
			else
				fprintf(stderr, "died by unknown reason\n");
		);
	}

out:
	die_childs = 0;
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
	INIT_LIST_HEAD(&p->chan_list);
	list_add(&p->chan_list, &channels);

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
	list_del(&chan->chan_list);
	free(chan);

	s->nchannel--;
}

static void serv_add_new(char *local_port, char *host, char *port)
{
	struct sockaddr_in sa;
	struct server *s;

	s = (struct server *) xmalloc(sizeof(*s));
	s->nchannel = 0;

	makeaddr(&s->remote_sa, host, port);
	s->remote_addr = addrstr(&s->remote_sa);

	memset(&sa, 0, sizeof(sa));
	makeaddr(&sa, "0.0.0.0", local_port);
	s->sock = tcp_server((struct sockaddr *) &sa, sizeof(sa));

	INIT_LIST_HEAD(&s->serv_list);
	list_add(&s->serv_list, &servers);
}

static inline int tcp_socket(void)
{
	int sock;

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		sys_err("socket");
	set_nonblock(sock);

	return sock;
}

static void usage(void)
{
	fprintf(stderr, "Usage: %s config_file\n", PROGNAME);
	exit(1);
}

static void on_quit(void)
{
	if (main_pid == getpid()) {
		if (UNIX_SOCKET_PATH[0] != '\0' && unlink(UNIX_SOCKET_PATH) < 0)
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
	if (se == NULL)
		err_quit("unknown service %s", name);

	return se->s_port;
}

static void makeaddr(struct sockaddr_in *sa, const char *host, const char *port)
{
	memset(sa, 0, sizeof(*sa));
	if (inet_aton(host, &sa->sin_addr) == 0)
		err_quit("inet_aton %s failed", host);

	sa->sin_family = AF_INET;
	sa->sin_port = portbyname(port);
}

static char *addrstr(struct sockaddr_in *sa)
{
	char buf[512];

	snprintf(buf, sizeof(buf), "%s:%d", inet_ntoa(sa->sin_addr),
		ntohs(sa->sin_port));
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

	sock = tcp_socket();
	flag = 1;

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0)
		sys_err("setsockopt SO_REUSEADDR failed");
	if (bind(sock, sa, addrlen) < 0)
		sys_err("bind");
	if (listen(sock, 7) < 0)
		sys_err("listen");

	return sock;
}

static inline int unix_socket(void)
{
	int sock;

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		sys_err("socket PF_UNIX");

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
		sys_err("fcntl");
	opts |= O_NONBLOCK;
	if (fcntl(desc, F_SETFL, opts) < 0)
		sys_err("fcntl");
}

static int add_chans(fd_set *readfds, fd_set *writefds, fd_set *exceptfds)
{
	struct channel *chan;
	struct buffer *b1, *b2;
	int fd1, fd2;
	int nfds = -1;

	list_for_each_entry(chan, &channels, chan_list) {
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

	list_for_each_entry(server, &servers, serv_list) {
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

static void test_chans(fd_set *readfds, fd_set *writefds, fd_set *exceptfds)
{
	struct channel *chan, *tmp;
	struct buffer *b1, *b2;
	int fd1, fd2;
	int n;

	list_for_each_entry_safe(chan, tmp, &channels, chan_list) {
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
			else
				DEBUG_CODE(
					msg_warn("read from %s %d bytes",
						chan->addr, n);
				);
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

		if (fd1 >= 0 && fd2 < 0 && bhasdata(b2) == 0)
			shut(&fd1);
		if (fd2 >= 0 && fd1 < 0 && bhasdata(b1) == 0)
			shut(&fd2);

		chan->fd1 = fd1;
		chan->fd2 = fd2;

		if (fd1 < 0 && fd2 < 0) {
			fprintf(stderr, "close: %s to %s\n", chan->addr,
				chan->server->remote_addr);
			chan_free(chan);
		}
	}
}

static void accept_client(struct server *server, int serv_sock)
{
	struct channel *chan;
	struct sockaddr_in sa;
	socklen_t salen;
	int fd1, fd2;
	int ret;

	salen = sizeof(sa);
	fd1 = accept(serv_sock, (struct sockaddr *) &sa, &salen);
	if (fd1 < 0) {
		if (errno != EAGAIN)
			msg_err("accept");
		return;
	}

	fd2 = tcp_socket();
	ret = connect(fd2, (struct sockaddr *) &server->remote_sa, sizeof(struct sockaddr_in));
	if (ret < 0 && errno != EINPROGRESS) {
		close(fd1);
		close(fd2);

		msg_err("connect");
		return;
	}

	chan = chan_new(server, addrstr(&sa), fd1, fd2);
	if (ret == 0)
		chan->connected++;

	fprintf(stderr, "accept: %s to %s\n", chan->addr, server->remote_addr);
}

static int test_servs(fd_set *readfds)
{
	struct server *server;
	int count = 0;

	list_for_each_entry(server, &servers, serv_list) {
		int fd = server->sock;

		if (FD_ISSET(fd, readfds)) {
			accept_client(server, fd);
			count++;
		}
	}

	return count;
}

static int store_info(char **ptr)
{
	struct channel *chan;
	FILE *stream;
	size_t size = 0;
	int total = 0;

	stream = open_memstream(ptr, &size);
	if (stream == NULL)
		sys_err("open_memstream");
	list_for_each_entry(chan, &channels, chan_list) {
		fprintf(stream, "%s => %s", chan->addr, chan->server->remote_addr);
		if (chan->connected == 0)
			fprintf(stream, ": not connected");
		fprintf(stream, "\n");
		total++;
	}

	fprintf(stream, "total: %d\n", total);
	fclose(stream);

	return size;
}

void send_info(int sock)
{
	char *buf = NULL;
	char *p;
	size_t size;
	int n;

	size = store_info(&buf);
	p = buf;
	while (size > 0) {
		n = write(sock, p, size);
		if (n < 0)
			sys_err("write");
		size -= n;
		p += n;
	}

	free(buf);
}

static void accept_unix(int unix_sock)
{
	pid_t pid;
	int sock;

	sock = accept(unix_sock, NULL, NULL);
	if (sock < 0) {
		if (errno != EAGAIN)
			msg_err("accept");
		return;
	}

	pid = fork();
	if (pid < 0) {
		msg_err("fork");
		return;
	}

	if (pid > 0) {
		close(sock);
		return;
	}

	send_info(sock);
	close(sock);
	exit(0);
}

static void endless_loop(int unix_sock)
{
	fd_set rd, wr, er;
	sigset_t set, pend_set;
	int nfds;
	int ret;

	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);

	for (;;) {
		if (die_childs)
			wait_childs();

		FD_ZERO(&rd);
		FD_ZERO(&wr);
		FD_ZERO(&er);

		FD_SET(unix_sock, &rd);

		nfds = max(add_servs(&rd), unix_sock);
		nfds = max(add_chans(&rd, &wr, &er), nfds);

		ret = select(nfds + 1, &rd, &wr, &er, NULL);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			sys_err("select");
		}

		xsigprocmask(SIG_BLOCK, &set, NULL);
		ret -= test_servs(&rd);

		if (ret > 0 && FD_ISSET(unix_sock, &rd)) {
			accept_unix(unix_sock);
			ret--;
		}

		if (ret > 0)
			test_chans(&rd, &wr, &er);

		xsigpending(&pend_set);
		if (sigismember(&pend_set, SIGCHLD))
			wait_childs();

		xsigprocmask(SIG_UNBLOCK, &set, NULL);
	}
}

