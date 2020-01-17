// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#ifndef __MANAGEMENT_NOTIFY_H__
#define __MANAGEMENT_NOTIFY_H__

#include "../linux/cifsd_server.h"

struct cifsd_notify_event {
	int				outdata_len;
	unsigned int	buf_len;
	unsigned char	buf[1];
};

struct cifsd_notify_info {
	unsigned int	action;
	unsigned int	filename_len;
	unsigned char	filename[0];
};

struct cifsd_notify_event *notimgr_handle_notify_request(struct cifsd_notify_request *req);
void notimgr_handle_notify_cancel_request(unsigned int hdl);
void notimgr_build_notify_response(struct cifsd_notify_response *rsp, struct cifsd_notify_event *evt);

#endif /* __MANAGEMENT_NOTIFY_H__ */

