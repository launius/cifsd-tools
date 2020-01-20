#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>

#include "config.h"
#include "clientd.h"
#include "log.h"

#define CLIENTD_ADDR		"192.168.176.101"
#define CLIENTD_PORT		28877

struct header {
	int type; /* one of MSG_XXX */
	int len;  /* length of current data */
	char data[0];
} __attribute__((packed));

static int sock = -1;
static struct sockaddr_in server_addr;

#if USING(FEATURE_CLIENTD_ASYNC)
static pthread_t tid;
#endif

static void flush_data(int fd, size_t len)
{
	int r;
	size_t s;
	char buf[256];

	while (len > 0) {
		s = len > sizeof(buf) ? sizeof(buf) : len;

		r = recv(fd, buf, s, 0);
		if (r < 0)
			break;

		len -= r;
	}
}

int proto_send(int fd, enum clientd_msgtype type, const char *data, int len)
{
	int r;
	struct header *hdr;
	char *buf;

	assert(fd >= 0);

	buf = malloc(sizeof(struct header) + len);
	if (!buf) {
		smbmgr_err("send: send buffer alloc error");
		return -1;
	}

	hdr = (struct header *)buf;
	hdr->type = type;
	hdr->len = len;

	if (len != 0)
		memcpy(hdr->data, data, len);

	r = send(fd, buf, sizeof(*hdr) + len, MSG_NOSIGNAL);
	free(buf);

	if (r < 0) {
		smbmgr_err("send: fd %d errno %d", fd, errno);
		return -1;
	}

	int hdr_size = (int) sizeof(*hdr);
	if (r != hdr_size + len)
		smbmgr_err("send: %d / %u byte", r, sizeof(*hdr) + len);

	return 0;
}

int proto_recv(int fd, enum clientd_msgtype *type, char **data, int *len)
{
	int r;
	struct header hdr;
	char *_data;

	assert(fd >= 0);
	assert(type);
	assert(data);
	assert(len);

	r = recv(fd, &hdr, sizeof(hdr), 0);
	if (r <= 0) {
		if (r == 0)
			smbmgr_info("recv: fd %d closed", fd);
		else
			smbmgr_err("recv: fd %d errno %d", fd, errno);
		return -1;
	}

	if (r != sizeof(hdr)) {
		smbmgr_err("recv: fd %d Invalid message", fd);
		return -1;
	}

	if (hdr.len == 0) {
		*type = hdr.type;
		*data = NULL;
		*len = 0;
		return 0;
	}

	_data = malloc(hdr.len);
	if (!_data) {
		flush_data(fd, (size_t)hdr.len);
		smbmgr_err("malloc fail");
		return -1;
	}
	
	smbmgr_info("pack len %d", hdr.len);
	r = recv(fd, _data, hdr.len, 0);
	if (r <= 0) {
		if (r == 0)
			smbmgr_err("recv: fd %d closed", fd);
		else
			smbmgr_err("recv: fd %d errno %d", fd, errno);

		free(_data);
		return -1;
	}

	if (r != hdr.len) {
		smbmgr_err("recv: fd %d expect size %d > received %d", fd, hdr.len, r);
		free(_data);
		return -1;
	}

	*type = hdr.type;
	*data = _data;
	*len = hdr.len;

	return 0;
}

static void send_msg(int fd, enum clientd_msgtype req_type)
{
	char *buff = NULL;
	int msg_len;
	enum clientd_msgtype rsp_type;

	proto_send(fd, req_type, NULL, 0);
	proto_recv(fd, &rsp_type, &buff, &msg_len);

	if (buff != NULL)
		free(buff);

	if (rsp_type != MSG_RSP)
		smbmgr_info("clientd resp error: %d", rsp_type);

	smbmgr_info("sent to clientd: %d", req_type);
}

int connect_sock()
{
	smbmgr_info("connecting to clientd %s:%d...", CLIENTD_ADDR, CLIENTD_PORT);

	if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		smbmgr_err("connect: connect errno %d", errno);
		close(sock);
		sock = -1;
		return -1;
	}

	smbmgr_info("clientd connected: %d", sock);
	return 0;
}

#if USING(FEATURE_CLIENTD_ASYNC)
void *connect_thread()
{
	smbmgr_info("async connection start");

	if (connect_sock() < 0)
		pthread_exit((void *) -1);

	send_msg(sock, MSG_SMB_MOUNT);
	pthread_exit((void *) 0);
}
#endif

int clientd_connect()
{
	int n;

	if ((sock = socket(PF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)) < 0) {
		smbmgr_err("connect: socket errno %d", errno);
		return -1;
	}

	bzero((char *)&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(CLIENTD_ADDR);
	server_addr.sin_port = htons(CLIENTD_PORT);

#if USING(FEATURE_CLIENTD_ASYNC)
	pthread_create(&tid, NULL, connect_thread, NULL);
#else
	if (connect_sock() < 0)
		return -1;
	send_msg(sock, MSG_SMB_MOUNT);
#endif
	
	return 0;
}

int clientd_notify_add()
{
	if (sock < 0) {
		smbmgr_err("clientd connection error: %d", sock);
		return -1;
	}

	send_msg(sock, MSG_SMB_USB_ADD);
	return 0;
}

int clientd_notify_delete()
{
	if (sock < 0) {
		smbmgr_err("clientd connection error: %d", sock);
		return -1;
	}

	send_msg(sock, MSG_SMB_USB_DELETE);
	return 0;
}

int clientd_close()
{
	if (sock < 0) {
		smbmgr_err("clientd connection error: %d", sock);
#if USING(FEATURE_CLIENTD_ASYNC)
		pthread_cancel(tid);
		pthread_join(tid, NULL);
		smbmgr_info("async connection canceled: %lu", tid);
#endif

		return -1;
	}

	send_msg(sock, MSG_SMB_UMOUNT);
	close(sock);
	sock = -1;

	return 0;
}

