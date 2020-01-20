#pragma once

#include <syslog.h>

#define smbmgr_info(fmt, ...) syslog(LOG_INFO, "smbmgr: " fmt, ##__VA_ARGS__)
#define smbmgr_err(fmt, ...) syslog(LOG_ERR, "smbmgr: " fmt, ##__VA_ARGS__)

#if !defined(DEBUG_LOG)
#define smbmgr_dbg(fmt, ...) do { } while (0)
#else /* DEBUG_LOG */
#define smbmgr_dbg(fmt, ...) \
	syslog(LOG_DEBUG, "smbmgr:%s:%d: " fmt, __func__, __LINE__, ##__VA_ARGS__)
#endif /* DEBUG_LOG */

