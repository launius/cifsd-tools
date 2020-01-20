#ifndef __SMBMGR_H__
#define __SMBMGR_H__

/**
 * @file smbmgr.h smb-manager public header
 */

#ifdef __cplusplus
extern "C" {
#endif

enum ipc_state {
	IPC_STATE_OK,
	IPC_STATE_ERROR,
	IPC_STATE_NOMEM,
	IPC_STATE_NOTCONN,
	IPC_STATE_TIMEDOUT,
	IPC_STATE_ACCES,
	IPC_STATE_AGAIN,
	IPC_STATE_INTR,
	IPC_STATE_INVAL,
	IPC_STATE_NOENT
};

int ipc_activate();
int ipc_connect(int *fd);
int ipc_send(int fd, const int cmd, char *data, char *ldata);
int ipc_recv(int fd);
int ipc_disconnect(int *fd);

int smbmgr_start();
int smbmgr_disk_add();
int smbmgr_disk_delete();
int smbmgr_stop();

#ifdef __cplusplus
}
#endif
#endif /* __SMBMGR_H__ */

