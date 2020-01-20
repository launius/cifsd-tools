#define _GNU_SOURCE

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/xattr.h>

#include <systemd/sd-daemon.h>

#include "config.h"
#include "socks.h"
#include "log.h"

#define SOCKET_TIMEOUT 5 /* seconds */

static int sock_create(const char *path)
{
	int r;
	int fd;
	struct sockaddr_un sa;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		smbmgr_err("Socket '%s': socket %d", path, errno);
		return -1;
	}

#if USING(!FEATURE_USER_PERMISSION)
	if((fsetxattr(fd, "security.SMACK64IPOUT", "@", 2, 0)) < 0) {
		smbmgr_err("Failed to set Socket SMACK label");
		if (errno != EOPNOTSUPP) {
			close(fd);
			return -1;
		}
	}

	if ((fsetxattr(fd, "security.SMACK64IPIN", "*", 2, 0)) < 0) {
		smbmgr_err("Failed to set Socket SMACK label");
		if (errno != EOPNOTSUPP) {
			close(fd);
			return -1;
		}
	}
#endif

	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, path, sizeof(sa.sun_path));
	sa.sun_path[sizeof(sa.sun_path) - 1] = '\0';

	r = unlink(sa.sun_path);
	if (r == -1 && errno != ENOENT) {
		smbmgr_err("Socket '%s': unlink %d", path, errno);
		close(fd);
		return -1;
	}

	r = bind(fd, (struct sockaddr *)&sa, sizeof(sa));
	if (r == -1) {
		smbmgr_err("Socket '%s': bind %d", path, errno);
		close(fd);
		return -1;
	}

	chmod(sa.sun_path, 0666);

	r = listen(fd, SOMAXCONN);
	if (r == -1) {
		smbmgr_err("Socket '%s': listen %d", path, errno);
		close(fd);
		return -1;
	}

	return fd;
}

int sock_get_server(const char *path)
{
	int n;
	int i;
	int r;
	int fd;

	if (!path || !*path) {
		errno = EINVAL;
		return -1;
	}

	n = sd_listen_fds(0);
	if (n < 0) {
		smbmgr_err("sd_listen_fds: %d", n);
		return -1;
	}

	smbmgr_info("the number of listen fds is %d", n);
	if (n == 0)
		return sock_create(path);

	fd = -1;
	for (i = SD_LISTEN_FDS_START; i < SD_LISTEN_FDS_START + n; i++) {
		r = sd_is_socket_unix(i, SOCK_STREAM, -1, path, 0);
		smbmgr_info("[launius] sd_is_socket_unix: %d:%d", i, r);
		if (r > 0) {
			fd = i;
			break;
		}
	}

	if (fd == -1) {
		smbmgr_err("Socket '%s' is not passed", path);
		return sock_create(path);
	}

	return fd;
}

int sock_set_client(int fd)
{
	int r;
	struct timeval tv;
	int on;

	r = fcntl(fd, F_SETFL, O_NONBLOCK);
	if (r == -1) {
		smbmgr_err("Client %d: set NONBLOCK: %d", fd, errno);
		return -1;
	}

	/* need SO_PRIORITY ? */

	tv.tv_sec = SOCKET_TIMEOUT;
	tv.tv_usec = 0;
	r = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (void *)&tv,
			sizeof(struct timeval));
	if (r == -1) {
		smbmgr_err("Client %d: set SO_RCVTIMEO: %d", fd, errno);
		return -1;
	}

	on = 1;
	r = setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on));
	if (r == -1)
		smbmgr_err("Client %d: set SO_PASSCRED: %d", fd, errno);

	return 0;
}

int sock_get_client_cred(int fd, struct ucred *cred)
{
	int r;
	socklen_t len;

	if (fd < 0 || !cred) {
		errno = EINVAL;
		return -1;
	}

	len = sizeof(*cred);
	r = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, cred, &len);
	if (r == -1) {
		smbmgr_err("Client %d: get SO_PEERCRED: %d", fd, errno);
		return -1;
	}

	smbmgr_info("Client %d: pid %d uid %u gid %u", fd,
			cred->pid, cred->uid, cred->gid);

	return 0;
}

int sock_cleanup(const char *path)
{
	unlink(path);
	smbmgr_info("deleted %s", path);
	
	return 0;
}

