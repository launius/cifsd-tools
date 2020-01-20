#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>

#include "smbmgr.h"
#include "common.h"
#include "log.h"

#define ACT_PATH		"/tmp/smbmgr_ready"
#define ACT_TIMESLOT	50
#define ACT_TIMEOUT		1500

struct smbmgr_adapter {
	int ipc_fd;
	int disk_cnt;
};

struct smbmgr_adapter sa = {-1, 0};

static char *get_random_port()
{
	static char port[] = "445";
	return port;
}

static void get_random_account()
{
	return;
}

static bool is_ipc_opened()
{
	return access(SOCKPATH, F_OK) ? false : true;
}

static int wait_ipc_open(int timeout_ms)
{
	int elapsed = 0, time_slot = ACT_TIMESLOT;
	int rc = -1;

	while (1) {
		if (is_ipc_opened()) {
			rc = 0;
			break;
		}

		if (elapsed >= timeout_ms)
			break;

		usleep(time_slot * 1000);
		elapsed += time_slot;
		smbmgr_info("waiting ipc open... %d", elapsed);
	}

	return rc;
}

static void clean_activation()
{
	if (!access(ACT_PATH, F_OK))
		unlink(ACT_PATH);

	smbmgr_info("deleted %s", ACT_PATH);
}

// TODO: not exporting
EXPORT int ipc_activate()
{
	int fd;
	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

	fd = open(ACT_PATH, O_RDONLY | O_CREAT | O_EXCL, mode);
	close(fd);

	smbmgr_info("ipc activated: %s", ACT_PATH);
	return IPC_STATE_OK;
}

EXPORT int smbmgr_start()
{
	int rc = IPC_STATE_OK;
	
	smbmgr_info("smb-manager start: fd %d, disk %d", sa.ipc_fd, sa.disk_cnt);

	// TODO: consider multi thread call
	if (!is_ipc_opened()) {
		sa.ipc_fd = -1;
		sa.disk_cnt = 0;

		ipc_activate();
		if (wait_ipc_open(ACT_TIMEOUT)) {
			smbmgr_err("smb-manager start fail!!");
			clean_activation();

			rc = IPC_STATE_ERROR;
			return rc;
		}
		clean_activation();
	}

	if (sa.ipc_fd > 0) {
		smbmgr_info("ipc already connected: fd %d", sa.ipc_fd);
		return rc;
	}

	rc = ipc_connect(&sa.ipc_fd);
	return rc;
}

EXPORT int smbmgr_disk_add()
{
	int cmd;
	int rc = IPC_STATE_OK;

	smbmgr_info("smb-manager disk add: fd %d, disk %d", sa.ipc_fd, sa.disk_cnt);

	if (sa.ipc_fd < 0) {
		smbmgr_err("ipc connection error: fd %d", sa.ipc_fd);
		rc = IPC_STATE_ERROR;
		return rc;
	}

	if (++sa.disk_cnt == 1) {
		cmd = CMD_PROC_START;
		rc = ipc_send(sa.ipc_fd, cmd, get_random_port(), NULL);
		if (rc != IPC_STATE_OK) {
			smbmgr_err("ipc send error: fd %d, cmd %d", sa.ipc_fd, cmd);
			return rc;
		}

		// TODO: check cifsd mount delay
		sleep(2);

		cmd = CMD_NOTIFY_START;
		if (ipc_send(sa.ipc_fd, cmd, NULL, NULL) !=  IPC_STATE_OK)
			smbmgr_err("ipc send error: fd %d, cmd %d", sa.ipc_fd, cmd);
	}

	cmd = CMD_NOTIFY_ADD;
	if (ipc_send(sa.ipc_fd, cmd, NULL, NULL) !=  IPC_STATE_OK)
		smbmgr_err("ipc send error: fd %d, cmd %d", sa.ipc_fd, cmd);

	return rc;
}

EXPORT int smbmgr_disk_delete()
{
	int cmd;
	int rc = IPC_STATE_OK;

	smbmgr_info("smb-manager disk delete: fd %d, disk %d", sa.ipc_fd, sa.disk_cnt);

	if (sa.ipc_fd < 0) {
		smbmgr_err("ipc connection error: fd %d", sa.ipc_fd);
		rc = IPC_STATE_ERROR;
		return rc;
	}

	--sa.disk_cnt;
	cmd = CMD_NOTIFY_DELETE;
	if (ipc_send(sa.ipc_fd, cmd, NULL, NULL) != IPC_STATE_OK)
		smbmgr_err("ipc send error: fd %d, cmd %d", sa.ipc_fd, cmd);

	if (sa.disk_cnt == 0) {
		cmd = CMD_NOTIFY_STOP;
		if (ipc_send(sa.ipc_fd, cmd, NULL, NULL) != IPC_STATE_OK)
			smbmgr_err("ipc send error: fd %d, cmd %d", sa.ipc_fd, cmd);

		cmd = CMD_PROC_STOP;
		rc = ipc_send(sa.ipc_fd, cmd, NULL, NULL);
		if (rc !=  IPC_STATE_OK)
			smbmgr_err("ipc send error: fd %d, cmd %d", sa.ipc_fd, cmd);
	}

	return rc;
}

EXPORT int smbmgr_stop()
{
	int cmd;
	int rc = IPC_STATE_OK;

	smbmgr_info("smb-manager stop: fd %d, disk %d", sa.ipc_fd, sa.disk_cnt);

	if (sa.ipc_fd < 0) {
		// TODO: forced kill smbmgrd and handle the kill signal on smbmgrd side
		smbmgr_err("ipc connection error: fd %d", sa.ipc_fd);
		rc = IPC_STATE_ERROR;
		return rc;
	}

	cmd = CMD_PROC_STOP;
	if (ipc_send(sa.ipc_fd, cmd, NULL, NULL) != IPC_STATE_OK)
		// TODO: print cmd string
		smbmgr_err("ipc send error: fd %d, cmd %d", sa.ipc_fd, cmd);

	if (ipc_send(sa.ipc_fd, CMD_PUT_FIN, NULL, NULL) == IPC_STATE_OK)
		ipc_recv(sa.ipc_fd);
	
	rc = ipc_disconnect(&sa.ipc_fd);
	sa.disk_cnt = 0;
	
	return rc;
}

