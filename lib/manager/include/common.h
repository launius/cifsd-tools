#pragma once

#include <stdint.h>

#ifndef EXPORT
#define EXPORT __attribute__((visibility("default")))
#endif

#ifndef SOCKPATH
#define SOCKPATH "/tmp/.smbmgr.sock"
#endif

// TODO: consider packet header and body for variable size
struct ipc_request {
	uint32_t msgid;
	uint8_t cmd;
	int8_t data[16];
	int8_t data_l[128];
} __attribute__((packed));

struct ipc_response {
	uint32_t msgid;
	uint8_t cmd;
	int32_t res;
} __attribute__((packed));

enum ipc_command {
	CMD_UNKNOWN			= 0,
	CMD_PROC_START,
	CMD_PROC_STOP,
	CMD_USER_ADD,
	CMD_USER_DELETE,
	CMD_SHARE_ADD		= 5,
	CMD_SHARE_DELETE,
	CMD_NOTIFY_START,
	CMD_NOTIFY_STOP,
	CMD_NOTIFY_ADD,
	CMD_NOTIFY_DELETE	= 10,
	CMD_GET_INFO,
	CMD_PUT_FIN,
	CMD_MAX
};

