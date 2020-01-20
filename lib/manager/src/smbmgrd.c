#define _GNU_SOURCE

#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <poll.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/xattr.h>

#include <glib.h>
#include <glib-unix.h>

#include "common.h"
#include "config.h"
#include "socks.h"
#include "cifsd.h"
#include "clientd.h"
#include "log.h"

#define SEND_TIMEOUT	100

struct smbmgr_context {
	GMainLoop *loop;

	int sock;
	guint sock_id;

	GHashTable *clients;
};

struct smbmgr_client {
	int fd;
	guint fd_id;

	struct ucred cred;
	struct smbmgr_context *sctx;
};

static void smbmgr_exit(struct smbmgr_context *ctx);

static guint check_client(struct smbmgr_context *ctx)
{
	guint n = g_hash_table_size(ctx->clients);
	smbmgr_info("client connection number: %u", n);

	return n;
}

static gboolean del_client(gpointer data)
{
	struct smbmgr_client *cli = data;

	assert(cli);
	assert(cli->sctx);
	assert(cli->sctx->clients);

	smbmgr_info("Client %p removed", cli);
	g_hash_table_remove(cli->sctx->clients, cli);

	return G_SOURCE_REMOVE;
}

static int recv_msg(int fd, struct ipc_request *msg, int sz)
{
	int r;

	r = recv(fd, msg, sz, 0);
	if (r <= 0) {
		if (r == 0)
			smbmgr_err("recv: fd %d closed", fd);
		else
//			if (errno != EAGAIN && errno != EINTR)
				smbmgr_err("recv: fd %d errno %d", fd, errno);

		return -1;
	}
	
	if (r != sz) {
		smbmgr_err("recv: fd %d Invalid message", fd);
		return -1;
	}

	smbmgr_info("received %dbytes: cmd %d data(%s,%s)", r, msg->cmd, msg->data, msg->data_l);
	return r;
}

static int send_msg(struct smbmgr_client *cli, struct ipc_response *msg)
{
	int r;
	struct pollfd fds[1];

	if (cli->fd < 0) {
		errno = EINVAL;
		return -1;
	}

	fds[0].fd = cli->fd;
	fds[0].events = POLLOUT;
	fds[0].revents = 0;

	do {
		r = poll(fds, 1, SEND_TIMEOUT);
		if (r == -1) {
			if (errno == EINTR)
				continue;

			smbmgr_err("send: fd %d poll errno %d", cli->fd, errno);
			return -1;
		} else if (r == 0) {
			smbmgr_err("send: fd %d poll timeout", cli->fd);
			errno = ETIMEDOUT;
			return -1;
		}
	} while (r < 0);

	r = send(cli->fd, msg, sizeof(struct ipc_response), MSG_NOSIGNAL);
	if (r == -1) {
		smbmgr_err("send: fd %d errno %d", cli->fd, errno);
		return -1;
	}

	smbmgr_info("sent %d/%dbytes: fd %d cmd %d", r, sizeof(struct ipc_response), cli->fd, msg->cmd);
	return 0;
}

static int proc_client_msg(struct smbmgr_client *cli, struct ipc_request *msg)
{
	gchar *arg1, *arg2;

	arg1 = g_strndup((gchar *)msg->data, sizeof(msg->data));
	arg2 = g_strndup((gchar *)msg->data_l, sizeof(msg->data_l));

	switch (msg->cmd) {
	case CMD_PROC_START:
		// TODO: check race condition
		if (check_client(cli->sctx) < 2)
			cifsd_start(arg1);
		break;
	case CMD_PROC_STOP:
		if (check_client(cli->sctx) < 2)
			cifsd_stop();
		break;
	case CMD_USER_ADD:
		cifsd_user_add(arg1, arg2);
		break;
	case CMD_USER_DELETE:
		cifsd_user_delete(arg1);
		break;
	case CMD_SHARE_ADD:
		cifsd_share_add(arg1, arg2);
		break;
	case CMD_SHARE_DELETE:
		cifsd_share_delete(arg1);
		break;
	case CMD_NOTIFY_START:
		clientd_connect();
		break;
	case CMD_NOTIFY_STOP:
		clientd_close();
		break;
	case CMD_NOTIFY_ADD:
		clientd_notify_add();
		break;
	case CMD_NOTIFY_DELETE:
		clientd_notify_delete();
		break;
	case CMD_PUT_FIN:
		smbmgr_info("proc msg: finish cmd %d", msg->cmd);
		break;
	case CMD_GET_INFO:
	default:
		smbmgr_err("proc msg: invalid cmd %d", msg->cmd);
		break;
	}
	
	g_free(arg1);
	g_free(arg2);

	return 0;
}

static gboolean client_cb(gint fd, GIOCondition cond, gpointer data)
{
	int r;
	struct smbmgr_client *cli = data;
	struct ipc_request req = {0,};
	struct ipc_response rsp = {0,};

	assert(cli);

	smbmgr_info("Client %d: cond 0x%x, pid(%d)", fd, cond, cli->cred.pid);

	if (cond & (G_IO_HUP | G_IO_ERR | G_IO_NVAL)) {
		if (cond & (G_IO_ERR | G_IO_NVAL))
			smbmgr_err("Client %d: PID %d(%s) IO %s", fd,
					cli->cred.pid, "label",
					cond & G_IO_ERR ?  "error" : "nval");

		cli->fd_id = 0;
		g_idle_add_full(G_PRIORITY_DEFAULT, del_client, cli, NULL);
		return G_SOURCE_REMOVE;
	}

	if (cli->cred.pid == 0)
		sock_get_client_cred(fd, &cli->cred);

	r = recv_msg(cli->fd, &req, sizeof(req));
	if (r == -1) {
		smbmgr_err("Client %d: recv error!! deleting client...", fd);

		cli->fd_id = 0;
		g_idle_add_full(G_PRIORITY_DEFAULT, del_client, cli, NULL);
		return G_SOURCE_REMOVE;
	}

	proc_client_msg(cli, &req);
	// TODO: handling return value

	// TODO: move checking of final response
	if (req.cmd == CMD_PUT_FIN) {
		rsp.cmd = req.cmd;
		rsp.res = 0;
		send_msg(cli, &rsp);
	}

	return G_SOURCE_CONTINUE;
}

static void add_client(struct smbmgr_context *ctx, int fd)
{
	int r;
	struct smbmgr_client *cli;

	r = sock_set_client(fd);
	if (r == -1) {
		close(fd);
		return;
	}

	cli = calloc(1, sizeof(*cli));
	if (!cli) {
		smbmgr_err("Client %d: %d", fd, errno);
		close(fd);
		return;
	}

	cli->fd = fd;
	cli->sctx = ctx;

	cli->fd_id = g_unix_fd_add(fd,
			G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
			client_cb, cli);

	g_hash_table_insert(ctx->clients, cli, cli);
	smbmgr_info("Client %p added, fd %d", cli, fd);
}

static gboolean accept_cb(gint fd, GIOCondition cond, gpointer data)
{
	struct smbmgr_context *ctx = data;
	int cfd;
	struct sockaddr sa;
	socklen_t addrlen;

	assert(ctx);

	smbmgr_info("Accept: server fd %d cond %x", fd, cond);

	addrlen = sizeof(sa);
	cfd = accept(fd, (struct sockaddr *)&sa, &addrlen);
	if (cfd == -1) {
		if (errno == EMFILE) {
			smbmgr_err("Too many open files, stop calling accept()");
			ctx->sock_id = 0;
			return G_SOURCE_REMOVE;
		}
		smbmgr_err("Accept: %d", errno);
		return G_SOURCE_CONTINUE;
	}

	smbmgr_info("Accepted client: fd %d", cfd);

	add_client(ctx, cfd);

	return G_SOURCE_CONTINUE;
}

static void resume_accept(struct smbmgr_context *ctx)
{
	assert(ctx);

	if (ctx->sock_id == 0) {
		smbmgr_err("Resume calling accept()");
		ctx->sock_id = g_unix_fd_add(ctx->sock, G_IO_IN, accept_cb, ctx);
	}
}

static void destroy_client(struct smbmgr_client *cli)
{
	struct smbmgr_context *ctx;

	if (!cli)
		return;

	ctx = cli->sctx;

	resume_accept(ctx);

	if (cli->fd_id)
		g_source_remove(cli->fd_id);

	if (cli->fd != -1)
		close(cli->fd);

	smbmgr_info("destroy client %p", cli);
	free(cli);

#if USING(FEATURE_FORCE_EXIT)
	// TODO: check exiting and activating simultaneously
	if (check_client(ctx) < 1) {
		smbmgr_exit(ctx);
		smbmgr_info("===== smbmgrd force-exit =====");
		exit(0);
	}
#endif
}

#if USING(FEATURE_SET_ACTIVATION)
static int set_activate_state()
{
	if((setxattr(ACT_PATH, "security.SMACK64", "*", strlen("*"), 0)) < 0) {
		smbmgr_err("Failed to set SMACK label on %s", ACT_PATH);
		return -1;
	}

	return 0;
}
#endif

static int smbmgr_init(struct smbmgr_context *ctx)
{
	smbmgr_info("initializing smb manager...");

	ctx->clients = g_hash_table_new_full(g_direct_hash, g_direct_equal,
			(GDestroyNotify)destroy_client, NULL);
	if (!ctx->clients)
		return -1;

	// TODO: consider signal handling callback

	ctx->sock = sock_get_server(SOCKPATH);
	if (ctx->sock == -1)
		return -1;

	smbmgr_info("created server socket %d", ctx->sock);
	ctx->sock_id = g_unix_fd_add(ctx->sock, G_IO_IN, accept_cb, ctx);

	// TODO: cifsd start automatically
	
	ctx->loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(ctx->loop);		// TODO: how to terminate loop

	return 0;
}

static void smbmgr_exit(struct smbmgr_context *ctx)
{
	smbmgr_info("exiting smb manager...");

	// TODO: cifsd stop automatically

	if (ctx->clients)
		g_hash_table_destroy(ctx->clients);

	if (ctx->loop)
		g_main_loop_unref(ctx->loop);

	if (ctx->sock != -1)
		close(ctx->sock);

	cifsd_cleanup();
	sock_cleanup(SOCKPATH);
}

int main(int argc, char *argv[])
{
	int ret;

	struct smbmgr_context sctx;

	smbmgr_info("===== smbmgrd start =====");

	ret = smbmgr_init(&sctx);

	smbmgr_exit(&sctx);

	smbmgr_info("===== smbmgrd end %d =====", ret);
}

