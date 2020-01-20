#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "common.h"
#include "smbmgr.h"
#include "log.h"

#define SEND_TIMEOUT 100

#define SIMPLE_CLIENT
#ifndef SIMPLE_CLIENT
struct ipc_client {
	int fd;
};

static GList *clients;
static pthread_mutex_t clients_lock = PTHREAD_MUTEX_INITIALIZER;
#endif

static int connect_server(const char *addr)
{
	int fd;
	struct sockaddr_un sa;
	int r;

	if (!addr) {
		errno = EINVAL;
		return -1;
	}

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd == -1) {
		smbmgr_err("connect: socket errno %d", errno);
		return -1;
	}

	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, addr, sizeof(sa.sun_path));
	sa.sun_path[sizeof(sa.sun_path) - 1] = '\0';

	r = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
	if (r == -1) {
		if (errno == ENOENT)
			smbmgr_err("connect: '%s' not exist", addr);
		else
			smbmgr_err("connect: connect errno %d", errno);

		close(fd);
		return -1;
	}

	return fd;
}

#ifdef SIMPLE_CLIENT
EXPORT int ipc_connect(int *fd)
{
	*fd = connect_server(SOCKPATH);
	if (*fd == -1) {
		smbmgr_err("ipc connect fail!!");
		return IPC_STATE_ERROR;
	}

	smbmgr_info("ipc connected: fd %d", *fd);
	return IPC_STATE_OK;
}
#else
EXPORT int ipc_connect()
{
	struct ipc_client *cli;

	// TODO: using macro
	pthread_mutex_lock(&clients_lock);

	cli = calloc(1, sizeof(*cli));
	if (!cli)
		return IPC_STATE_NOMEM;

	cli->fd = -1;
	cli->fd = connect_server(SOCKPATH);
	if (cli->fd == -1) {
		free_client(cli);
		pthread_mutex_unlock(&clients_lock);
		smbmgr_err("ipc connect fail!!");
		return IPC_STATE_ERROR;
	}

	clients = g_list_append(clients, cli);

	pthread_mutex_unlock(&clients_lock);

	smbmgr_info("ipc connected: fd %d", cli->fd);
	return IPC_STATE_OK;
}
#endif

EXPORT int ipc_send(int fd, const int cmd, char *data, char *ldata)
{
	int r;
	struct ipc_request msg = {0,};
	struct pollfd fds[1];
	size_t len;

	if (fd == -1) {
		errno = ENOTCONN;
		smbmgr_err("ipc not connected");
		return IPC_STATE_NOTCONN;
	}

	msg.cmd = cmd;
	if (data) {
		len = strlen(data) < sizeof(msg.data) ? strlen(data) : sizeof(msg.data);
		memcpy(msg.data, data, len);
	}
	if (ldata) {
		len = strlen(ldata) < sizeof(msg.data_l) ? strlen(ldata) : sizeof(msg.data_l);
		memcpy(msg.data_l, ldata, len);
	}

	fds[0].fd = fd;
	fds[0].events = POLLOUT;
	fds[0].revents = 0;

	do {
		r = poll(fds, 1, SEND_TIMEOUT);
		if (r == -1) {
			if (errno == EINTR)
				continue;

			smbmgr_err("send: fd %d poll errno %d", fd, errno);
			return IPC_STATE_ERROR;
		} else if (r == 0) {
			smbmgr_err("send: fd %d poll timeout", fd);
			errno = ETIMEDOUT;
			return IPC_STATE_TIMEDOUT;
		}
	} while (r < 0);

	r = send(fd, &msg, sizeof(msg), MSG_NOSIGNAL);
	if (r == -1) {
		smbmgr_err("send: fd %d errno %d", fd, errno);
		return IPC_STATE_ERROR;
	}

	if (r != sizeof(msg))
		smbmgr_err("send: %d/%dbytes", r, (int32_t)(sizeof(msg)));

	smbmgr_info("ipc sent %dbytes: fd %d cmd %d data(%s,%s)", r, fd, cmd, data, ldata);
	return IPC_STATE_OK;
}

EXPORT int ipc_recv(int fd)
{
	int r;
	struct ipc_response msg = {0,};

	if (fd == -1) {
		errno = ENOTCONN;
		smbmgr_err("ipc not connected");
		return IPC_STATE_NOTCONN;
	}

	smbmgr_info("ipc receiving... fd %d", fd);
	r = recv(fd, &msg, sizeof(msg), MSG_WAITALL);
	if (r <= 0) {
		if (r == 0)
			smbmgr_err("recv: fd %d closed", fd);
		else
			smbmgr_err("recv: fd %d errno %d", fd, errno);

		return IPC_STATE_ERROR;
	}

	smbmgr_info("ipc received %dbytes: fd %d cmd %d res %d", r, fd, msg.cmd, msg.res);
	return IPC_STATE_OK;
}

#ifdef SIMPLE_CLIENT
EXPORT int ipc_disconnect(int *fd)
{
	if (*fd != -1) {
		close(*fd);
		*fd = -1;
	}

	smbmgr_info("ipc disconnected: fd %d", *fd);
	return IPC_STATE_OK;
}
#else
EXPORT int ipc_disconnect(struct ipc_client *cli)
{
	if (!cli)
		return IPC_STATE_NOTCONN;

	if (cli->fd != -1) {
		close(cli->fd);
		cli->fd = -1;
	}

	free(cli);
	smbmgr_info("ipc disconnected: fd %d", cli->fd);

	return IPC_STATE_OK;
}
#endif

