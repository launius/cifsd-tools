enum clientd_msgtype {
	MSG_UNKNOWN = 0,
	MSG_SMB_MOUNT,
	MSG_SMB_UMOUNT,
	MSG_SMB_USB_ADD,
	MSG_SMB_USB_DELETE,
	MSG_RSP,
	MSG_RSP_ERR,
	MSG_MAX,
};

int clientd_connect();
int clientd_notify_add();
int clientd_notify_delete();
int clientd_close();

