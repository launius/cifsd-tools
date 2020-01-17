// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#include <stdbool.h>
#include <sys/inotify.h>

#include <management/notify.h>
#include <cifsdtools.h>

#define EVENT_SIZE	(sizeof(struct inotify_event))
#define BUF_LEN		(8 * (EVENT_SIZE + 16))

#define MAX_NOTIFY	16

//TODO: consider to change to linked list
struct inotify_desc
{
	int fd;
	int wd;
} desc_list[MAX_NOTIFY];


static struct cifsd_notify_event *event_alloc()
{
	struct cifsd_notify_event *ptr = NULL;

	ptr = (struct cifsd_notify_event *)malloc(offsetof(struct cifsd_notify_event, buf) + BUF_LEN);
	ptr->outdata_len = 0;

	return ptr;
}

static void event_free(struct cifsd_notify_event *ptr)
{
	if (ptr) {
		free(ptr);
		ptr = NULL;
	}
}

static int open_inotify_fd(void)
{
	int fd;
	int flags = 0;
	
	fd = inotify_init1(flags);
	if (fd < 0)
		pr_err("%s: %s: inotify fd %d\n", __func__, strerror(errno), fd);

	return fd;
}

static int watch_dir(int fd, const char *path, unsigned int mask)
{
	int wd;

	wd = inotify_add_watch(fd, path, mask);
	if (wd < 0)
		pr_err("%s: %s: inotify fd %d, path (%s)\n", __func__, strerror(errno), fd, path);

	return wd;
}

static int read_event(int fd, char *buf)
{
	int len;

	len = read(fd, buf, BUF_LEN);
	if (len < 0)
		pr_err("%s: %s: inotify fd %d\n", __func__, strerror(errno), fd);

	return len;
}

static int process_event(struct cifsd_notify_event *e, bool dir)
{
	int ret = 0, offset;
	unsigned char *p;
	struct inotify_event *event;

	offset = offsetof(struct cifsd_notify_info, filename);

	for (p = e->buf ; p < e->buf + e->buf_len ; p += EVENT_SIZE + event->len) {
		event = (struct inotify_event *)p;

		pr_debug("%s: event wd %d, mask 0x%08x, cookie %u, len %u\n",
			__func__, event->wd, event->mask, event->cookie, event->len);

		if (event->mask & IN_IGNORED) {
			pr_debug("%s: inotify was cancelled.\n", __func__);
			ret = -1;
			break;
		}
		else if ((event->mask & IN_ISDIR) == dir) {
			if (event->len) {
				pr_debug("%s: event name (%s), %dbytes\n", __func__, event->name, strlen(event->name));
				ret += offset + strlen(event->name);
			}
			else
				ret += offset;
		}
	}

	return ret;
}

static void handle_event(unsigned char *rsp_buf, unsigned char *ev_buf, unsigned int ev_len)
{
	unsigned char *p;
	struct inotify_event *event;
	struct cifsd_notify_info *info;

	for (p = ev_buf ; p < ev_buf + ev_len ; p += EVENT_SIZE + event->len) {
		event = (struct inotify_event *)p;
		info = (struct cifsd_notify_info *)rsp_buf;

		if (event->len) {
			pr_debug("%s: event wd %d, mask 0x%08x, cookie %u, len %u, name (%s) %d\n",
				__func__, event->wd, event->mask, event->cookie, event->len, event->name, strlen(event->name));

//			info->filename_len = event->len;	//TODO: check real filename length
			info->filename_len = strlen(event->name);
			strncpy(info->filename, event->name, info->filename_len);

			switch (event->mask & (IN_ALL_EVENTS | IN_UNMOUNT | IN_Q_OVERFLOW | IN_IGNORED)) {
			case IN_CREATE:
				info->action = CIFSD_NOTIFY_FLAG_ADDED;
				break;
			case IN_DELETE:
				info->action = CIFSD_NOTIFY_FLAG_REMOVED;
				break;
			case IN_MOVED_FROM:
				info->action = CIFSD_NOTIFY_FLAG_RENAMED_OLD_NAME;
				break;
			case IN_MOVED_TO:
				info->action = CIFSD_NOTIFY_FLAG_RENAMED_NEW_NAME;
				break;
			default:
				info->action = CIFSD_NOTIFY_FLAG_INVALID;
				break;
			}

			pr_debug("built Notify Info!! action %u, filename_len %u, filename (%s)\n", info->action, info->filename_len, info->filename);

			rsp_buf += offsetof(struct cifsd_notify_info, filename) + info->filename_len;
		}
	}
}

struct cifsd_notify_event *notimgr_handle_notify_request(struct cifsd_notify_request *req)
{
	struct inotify_desc *desc = desc_list + req->handle;;
	struct cifsd_notify_event *evt = NULL;

	if (!desc->fd)
		if ((desc->fd = open_inotify_fd()) < 0) {
			pr_err("%s: failed to open inotify fd.\n", __func__);
			goto out;
		}

	if (!desc->wd)
		if ((desc->wd = watch_dir(desc->fd, req->path, IN_CLOSE_WRITE | IN_CREATE | IN_DELETE | IN_MOVE)) < 0) {
			pr_err("%s: failed to watch.\n", __func__);
			goto out1;
		}

	evt = event_alloc();
	while (1) {
		pr_debug("%s: waiting event on (%s)... handle %d, is_dir %u, fd %d\n", __func__, req->path, req->handle, req->is_dir, desc->fd);
		evt->buf_len = read_event(desc->fd, evt->buf);
		pr_debug("%s: read event %ubytes!! handle %d, is_dir %u, fd %d\n", __func__, evt->buf_len, req->handle, req->is_dir, desc->fd);
		if (evt->buf_len < 0) {
			pr_err("%s: failed to read from inotify.\n", __func__);
			event_free(evt);
			goto out2;
		}

		evt->outdata_len = process_event(evt, req->is_dir);
		if (evt->outdata_len)
			goto out;
	}

out2:
	if (inotify_rm_watch(desc->fd, desc->wd)) {
		pr_err("%s: %s: failed to remove watch. fd = %d, wd = %d\n", __func__, strerror(errno), desc->fd, desc->wd);
		desc->wd = 0;
	}

out1:
	close(desc->fd);
	desc->fd = 0;

out:
	return evt;
}

void notimgr_handle_notify_cancel_request(unsigned int hdl)
{
	struct inotify_desc *desc = desc_list + hdl;

	pr_debug("%s: handle = %d, fd = %d, wd = %d\n", __func__, hdl, desc->fd, desc->wd);

	if (inotify_rm_watch(desc->fd, desc->wd))
		pr_err("%s: %s: inotify fd = %d, wd = %d\n", __func__, strerror(errno), desc->fd, desc->wd);
	close(desc->fd);

	desc->fd = desc ->wd = 0;
}

/*void notimgr_cleanup_notify_request(unsigned int hdl)
{
	struct inotify_desc *desc = desc_list + hdl;

	pr_debug("%s: handle = %d, fd = %d, wd = %d\n", __func__, hdl, desc->fd, desc->wd);

	if (inotify_rm_watch(desc->fd, desc->wd))
		pr_err("%s: %s: failed to remove watch.\n", __func__, strerror(errno));
	close(desc->fd);

	desc->fd = desc ->wd = 0;
}*/

void notimgr_build_notify_response(struct cifsd_notify_response *rsp, struct cifsd_notify_event *evt)
{
	if (!rsp) {
		event_free(evt);
		return;
	}

	pr_debug("%s: handle %d, outdata %dbytes\n", __func__, rsp->handle, evt->outdata_len);

	rsp->outbuf_sz = evt->outdata_len;
	handle_event(rsp->outbuf, evt->buf, evt->buf_len);

	event_free(evt);
}

