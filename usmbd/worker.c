// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */
#include <memory.h>
#include <glib.h>
#include <errno.h>
#include <linux/smbd_server.h>

#include <smbdtools.h>
#include <worker.h>
#include <ipc.h>
#include <rpc.h>

#include <management/user.h>
#include <management/share.h>
#include <management/tree_conn.h>

#define MAX_WORKER_THREADS	4
static GThreadPool *pool;

#define VALID_IPC_MSG(m,t) 					\
	({							\
		int ret = 1;					\
		if (((m)->sz != sizeof(t))) {			\
			pr_err("Bad message: %s\n", __func__);	\
			ret = 0;				\
		}						\
		ret;						\
	})

static int login_request(struct smbd_ipc_msg *msg)
{
	struct smbd_login_request *req;
	struct smbd_login_response *resp;
	struct smbd_ipc_msg *resp_msg;

	resp_msg = ipc_msg_alloc(sizeof(*resp));
	if (!resp_msg)
		goto out;

	req = SMBD_IPC_MSG_PAYLOAD(msg);
	resp = SMBD_IPC_MSG_PAYLOAD(resp_msg);

	resp->status = SMBD_USER_FLAG_INVALID;
	if (VALID_IPC_MSG(msg, struct smbd_login_request))
		usm_handle_login_request(req, resp);

	resp_msg->type = SMBD_EVENT_LOGIN_RESPONSE;
	resp->handle = req->handle;

	ipc_msg_send(resp_msg);
out:
	ipc_msg_free(resp_msg);
	return 0;
}

static int tree_connect_request(struct smbd_ipc_msg *msg)
{
	struct smbd_tree_connect_request *req;
	struct smbd_tree_connect_response *resp;
	struct smbd_ipc_msg *resp_msg;

	resp_msg = ipc_msg_alloc(sizeof(*resp));
	if (!resp_msg)
		goto out;

	req = SMBD_IPC_MSG_PAYLOAD(msg);
	resp = SMBD_IPC_MSG_PAYLOAD(resp_msg);

	resp->status = SMBD_TREE_CONN_STATUS_ERROR;
	resp->connection_flags = 0;

	if (VALID_IPC_MSG(msg, struct smbd_tree_connect_request))
		tcm_handle_tree_connect(req, resp);

	resp_msg->type = SMBD_EVENT_TREE_CONNECT_RESPONSE;
	resp->handle = req->handle;

	ipc_msg_send(resp_msg);
out:
	ipc_msg_free(resp_msg);
	return 0;
}

static int share_config_request(struct smbd_ipc_msg *msg)
{
	struct smbd_share_config_request *req;
	struct smbd_share_config_response *resp;
	struct smbd_share *share = NULL;
	struct smbd_ipc_msg *resp_msg;
	int payload_sz = 0;

	req = SMBD_IPC_MSG_PAYLOAD(msg);
	if (VALID_IPC_MSG(msg, struct smbd_share_config_request)) {
		share = shm_lookup_share(req->share_name);
		if (share)
			payload_sz = shm_share_config_payload_size(share);
	}

	resp_msg = ipc_msg_alloc(sizeof(*resp) + payload_sz);
	if (!resp_msg)
		goto out;

	resp = SMBD_IPC_MSG_PAYLOAD(resp_msg);
	shm_handle_share_config_request(share, resp);
	resp_msg->type = SMBD_EVENT_SHARE_CONFIG_RESPONSE;
	resp->handle = req->handle;

	ipc_msg_send(resp_msg);
out:
	put_smbd_share(share);
	ipc_msg_free(resp_msg);
	return 0;
}

static int tree_disconnect_request(struct smbd_ipc_msg *msg)
{
	struct smbd_tree_disconnect_request *req;

	if (!VALID_IPC_MSG(msg, struct smbd_tree_disconnect_request))
		return -EINVAL;

	req = SMBD_IPC_MSG_PAYLOAD(msg);
	tcm_handle_tree_disconnect(req->session_id, req->connect_id);

	return 0;
}

static int logout_request(struct smbd_ipc_msg *msg)
{
	if (!VALID_IPC_MSG(msg, struct smbd_logout_request))
		return -EINVAL;

	return 0;
}

static int heartbeat_request(struct smbd_ipc_msg *msg)
{
	if (!VALID_IPC_MSG(msg, struct smbd_heartbeat))
		return -EINVAL;

	pr_debug("HEARTBEAT frame from the server\n");
	return 0;
}

static int rpc_request(struct smbd_ipc_msg *msg)
{
	struct smbd_rpc_command *req;
	struct smbd_rpc_command *resp;
	struct smbd_ipc_msg *resp_msg;
	int ret = -ENOTSUP;

	req = SMBD_IPC_MSG_PAYLOAD(msg);
	if (req->flags & SMBD_RPC_METHOD_RETURN)
		resp_msg = ipc_msg_alloc(SMBD_IPC_MAX_MESSAGE_SIZE -
				sizeof(struct smbd_rpc_command));
	else
		resp_msg = ipc_msg_alloc(sizeof(struct smbd_rpc_command));
	if (!resp_msg)
		goto out;

	resp = SMBD_IPC_MSG_PAYLOAD(resp_msg);

	if ((req->flags & SMBD_RPC_RAP_METHOD) == SMBD_RPC_RAP_METHOD) {
		pr_err("RAP command is not supported yet %x\n", req->flags);
		ret = SMBD_RPC_ENOTIMPLEMENTED;
	} else if (req->flags & SMBD_RPC_OPEN_METHOD) {
		ret = rpc_open_request(req, resp);
	} else if (req->flags & SMBD_RPC_CLOSE_METHOD) {
		ret = rpc_close_request(req, resp);
	} else if (req->flags & SMBD_RPC_IOCTL_METHOD) {
		ret = rpc_ioctl_request(req, resp, resp_msg->sz);
	} else if (req->flags & SMBD_RPC_WRITE_METHOD) {
		ret = rpc_write_request(req, resp);
	} else if (req->flags & SMBD_RPC_READ_METHOD) {
		ret = rpc_read_request(req, resp, resp_msg->sz);
	} else {
		pr_err("Unknown RPC method: %x\n", req->flags);
		ret = SMBD_RPC_ENOTIMPLEMENTED;
	}

	resp_msg->type = SMBD_EVENT_RPC_RESPONSE;
	resp->handle = req->handle;
	resp->flags = ret;
	resp_msg->sz = sizeof(struct smbd_rpc_command) + resp->payload_sz;

	ipc_msg_send(resp_msg);
out:
	ipc_msg_free(resp_msg);
	return 0;
}

static void worker_pool_fn(gpointer event, gpointer user_data)
{
	struct smbd_ipc_msg *msg = (struct smbd_ipc_msg *)event;

	switch (msg->type) {
	case SMBD_EVENT_LOGIN_REQUEST:
		login_request(msg);
		break;

	case SMBD_EVENT_TREE_CONNECT_REQUEST:
		tree_connect_request(msg);
		break;

	case SMBD_EVENT_TREE_DISCONNECT_REQUEST:
		tree_disconnect_request(msg);
		break;

	case SMBD_EVENT_LOGOUT_REQUEST:
		logout_request(msg);
		break;

	case SMBD_EVENT_SHARE_CONFIG_REQUEST:
		share_config_request(msg);
		break;

	case SMBD_EVENT_RPC_REQUEST:
		rpc_request(msg);
		break;

	case SMBD_EVENT_HEARTBEAT_REQUEST:
		heartbeat_request(msg);
		break;

	default:
		pr_err("Unknown IPC message type: %d\n", msg->type);
		break;
	}

	ipc_msg_free(msg);
}

int wp_ipc_msg_push(struct smbd_ipc_msg *msg)
{
	return g_thread_pool_push(pool, msg, NULL);
}

void wp_destroy(void)
{
	if (pool)
		g_thread_pool_free(pool, 1, 1);
}

int wp_init(void)
{
	GError *err;

	pool = g_thread_pool_new(worker_pool_fn,
				 NULL,
				 MAX_WORKER_THREADS,
				 0,
				 &err);
	if (!pool) {
		if (err) {
			pr_err("Can't create pool: %s\n", err->message);
			g_error_free(err);
		}
		goto out_error;
	}

	return 0;
out_error:
	wp_destroy();
	return -ENOMEM;
}
