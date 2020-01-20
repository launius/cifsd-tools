#include <stdlib.h>
#include <signal.h>
#include <glib.h>
#include <gio/gio.h>

#include "config.h"
#include "cifsd.h"
#include "log.h"

#define CIFSD_NAME			"cifsd"
#define CIFSD_MODULE		"/usr/lib/modules/4.1.10/kernel/cifsd.ko"

#define CIFSD_BIN			"/usr/bin/cifsd"
#define CIFSD_USER			"/usr/bin/cifsuseradd"
#define CIFSD_SHARE			"/usr/bin/cifsshareadd"

#define CIFSD_CONF_RO		"/etc/cifs/smb.conf"
#define CIFSD_CONF			"/tmp/smb.conf"
#define CIFSD_DB			"/tmp/cifsdpwd.db"
#define CIFSD_STATS			"/sys/class/cifsd-control/stats"
#define CIFSD_LOCK			"/tmp/cifsd.lock"

enum proc_state {
	UNKNOWN,
	READY,
	RUNNING,
	WAITING,
	TERMINATED
};

static pthread_mutex_t cifsd_lock = PTHREAD_MUTEX_INITIALIZER;

#if USING(FEATURE_USER_PERMISSION)
#define insert_module()		insmod_user()
#define remove_module()		rmmod_user()
#else
#define insert_module()		insmod_super()
#define remove_module()		rmmod_super()
#endif

#if !USING(FEATURE_CIFSD_CONF_WRITABLE)
#define set_conf()
#endif

#if USING(FEATURE_USER_PERMISSION)
static int insmod_user()
{
	smbmgr_info("not supported");
	return 0;
}

static int rmmod_user()
{
	smbmgr_info("not supported");
	return 0;
}
#else
static int insmod_super()
{
	gchar command_line[64];
	gint child_status;
	g_autoptr(GError) error = NULL;

	g_snprintf(command_line, sizeof(command_line),
			"%s %s", "insmod", CIFSD_MODULE);

	g_spawn_command_line_sync(command_line, NULL, NULL, &child_status, &error);
	if (error != NULL) {
		smbmgr_err("spawning 'insmod' failed: %s", error->message);
		return -1;
	}

	smbmgr_info("inserted cifsd module");
	return 0;
}

static int rmmod_super()
{
	//TODO: make spawn function
	gchar command_line[64];
	gint child_status;
	g_autoptr(GError) error = NULL;

	g_snprintf(command_line, sizeof(command_line),
			"%s %s", "rmmod", CIFSD_NAME);

	g_spawn_command_line_sync(command_line, NULL, NULL, &child_status, &error);
	if (error != NULL) {
		smbmgr_err("spawning 'rmmod' failed: %s", error->message);
		return -1;
	}

	smbmgr_info("removed cifsd module");
	return 0;
}
#endif

static int get_cifsd_pid()
{
	gsize length;
	gchar *contents;
	int pid = -1;

	if (g_file_get_contents(CIFSD_LOCK, &contents, &length, NULL)) {
		pid = atoi(contents);
		smbmgr_info("cifsd pid: %d", pid);
		
		g_free(contents);
	}

	return pid;
}

static int check_kcifsd_state()
{
	gsize length;
	gchar *contents;
	gchar **tokens;
	int state = UNKNOWN;

	if (g_file_get_contents(CIFSD_STATS, &contents, &length, NULL)) {
		tokens = g_strsplit(contents, " ", -1);
		smbmgr_info("cifsd stats: %s", contents);

		// TODO: check stats tokens[1]

		g_strfreev(tokens);
		g_free(contents);
	}
	
	return state;
}

static int check_cifsd_state()
{
	int state = UNKNOWN;
	int pid;

	pid = get_cifsd_pid();
	if (pid < 0)
		state = TERMINATED;

	// TODO: check /proc/pid/stats

	return state;
}

#if USING(FEATURE_CIFSD_CONF_WRITABLE)
static void set_conf()
{
	GFile *in, *out;
	g_autoptr(GError) error = NULL;

	in = g_file_new_for_path(CIFSD_CONF_RO);
	out = g_file_new_for_path(CIFSD_CONF);

	g_file_copy(in, out, G_FILE_COPY_OVERWRITE, NULL, NULL, NULL, &error);
	if (error != NULL) {
		smbmgr_err("copying cifsd conf failed: %s", error->message);
		return;
	}

	smbmgr_info("copied cifsd conf");
}
#endif

#if USING(FEATURE_CIFSD_SPAWN_ASYNC)
// TODO: check login fail if defined #define SPAWN_ASYNC
static void child_watch_cb(GPid pid, gint status, gpointer user_data)
{
	smbmgr_info("Child %" G_PID_FORMAT " exited %s", pid,
			g_spawn_check_exit_status (status, NULL) ? "normally" : "abnormally");

	g_spawn_close_pid(pid);
}

int cifsd_start(const char *tcp_port)
{
	const gchar* const argv[] = {CIFSD_BIN, "-n -u " CIFSD_DB, NULL};
	gint child_stdout, child_stderr;
	GPid child_pid;
	g_autoptr(GError) error = NULL;
	int port = atoi(tcp_port);

	pthread_mutex_lock(&cifsd_lock);
	
	if (check_cifsd_state() == RUNNING) {
		pthread_mutex_unlock(&cifsd_lock);
		return 0;
	}

	insert_module();
	set_conf();

	g_spawn_async_with_pipes(NULL, (gchar **)argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, NULL,
							NULL, &child_pid, NULL, &child_stdout,
							&child_stderr, &error);
	if (error != NULL) {
		smbmgr_err("spawning cifsd failed: %s", error->message);
		pthread_mutex_unlock(&cifsd_lock);
		return -1;
	}

	g_child_watch_add (child_pid, child_watch_cb, NULL);
	smbmgr_info("cifsd started!! pid %d, port %d", child_pid, port);

	pthread_mutex_unlock(&cifsd_lock);
	return 0;
}
#else
int cifsd_start(const char *tcp_port)
{
	gchar command_line[64];
	gint child_status;
	g_autoptr(GError) error = NULL;
	int port = atoi(tcp_port);

	pthread_mutex_lock(&cifsd_lock);

	if (check_cifsd_state() == RUNNING) {
		pthread_mutex_unlock(&cifsd_lock);
		return 0;
	}

	insert_module();
	set_conf();

	g_snprintf(command_line, sizeof(command_line),
			"%s -c %s -u %s", CIFSD_BIN, CIFSD_CONF, CIFSD_DB);
	smbmgr_info("(%s)", command_line);

	g_spawn_command_line_sync(command_line, NULL, NULL, &child_status, &error);
	if (error != NULL) {
		smbmgr_err("spawning cifsd failed: %s", error->message);
		pthread_mutex_unlock(&cifsd_lock);
		return -1;
	}

	smbmgr_info("cifsd started!! port %d", port);
	pthread_mutex_unlock(&cifsd_lock);

	return 0;
}
#endif

static int get_sysfs()
{
	const gchar *command_line = "cat /sys/class/cifsd-control/kill_server";
	gint child_status;
	g_autoptr(GError) error = NULL;

	g_spawn_command_line_sync(command_line, NULL, NULL, &child_status, &error);
	if (error != NULL) {
		smbmgr_err("spawning failed: %s", error->message);
		return -1;
	}

	smbmgr_info("read kcifsd sysfs: %s", command_line);
	return 0;
}

int cifsd_stop()
{
	int pid;
	
	pthread_mutex_lock(&cifsd_lock);

	pid = get_cifsd_pid();
	if (pid < 0) {
		smbmgr_err("cifsd already stopped!! pid %d", pid);
		pthread_mutex_unlock(&cifsd_lock);
		return -1;
	}

	get_sysfs();
	kill(pid, SIGTERM);
	smbmgr_info("cifsd stopped!! pid %d", pid);

	remove_module();
	pthread_mutex_unlock(&cifsd_lock);

	return 0;
}

int cifsd_user_add(const char *id, const char * const pw)
{
	gchar command_line[128];
	gint child_status;
	g_autoptr(GError) error = NULL;

	pthread_mutex_lock(&cifsd_lock);

	g_snprintf(command_line, sizeof(command_line),
			"%s -i %s -a %s -p %s", CIFSD_USER, CIFSD_DB, id, pw);

	g_spawn_command_line_sync(command_line, NULL, NULL, &child_status, &error);
	if (error != NULL)
	{
		smbmgr_err("spawning 'cifsadmin -a' failed: %s", error->message);
		pthread_mutex_unlock(&cifsd_lock);
		return -1;
	}

	smbmgr_info("cifsd user added!! id(%s) pw(%s)", id, pw);
	pthread_mutex_unlock(&cifsd_lock);

	return 0;
}

int cifsd_user_delete(const char *id)
{
	gchar command_line[128];
	gint child_status;
	g_autoptr(GError) error = NULL;

	pthread_mutex_lock(&cifsd_lock);

	g_snprintf(command_line, sizeof(command_line),
			"%s -i %s -d %s", CIFSD_USER, CIFSD_DB, id);

	g_spawn_command_line_sync(command_line, NULL, NULL, &child_status, &error);
	if (error != NULL)
	{
		smbmgr_err("spawning 'cifsadmin -d' failed: %s", error->message);
		pthread_mutex_unlock(&cifsd_lock);
		return -1;
	}

	smbmgr_info("cifsd user deleted!! id(%s)", id);
	pthread_mutex_unlock(&cifsd_lock);

	return 0;
}

void cifsd_share_add(const char *name, const char *path)
{
	gchar command_line[256];
	gint child_status;
	g_autoptr(GError) error = NULL;

	pthread_mutex_lock(&cifsd_lock);

	g_snprintf(command_line, sizeof(command_line),
			"%s -a %s -o \"path=%s writeable=yes read only = no\" -c %s", CIFSD_SHARE, name, path, CIFSD_CONF);
	smbmgr_info("(%s)", command_line);

	g_spawn_command_line_sync(command_line, NULL, NULL, &child_status, &error);
	if (error != NULL)
		smbmgr_err("spawning 'cifsshareadd -a' failed: %s", error->message);

	pthread_mutex_unlock(&cifsd_lock);
}

void cifsd_share_delete(const char *name)
{
	gchar command_line[64];
	gint child_status;
	g_autoptr(GError) error = NULL;

	pthread_mutex_lock(&cifsd_lock);

	g_snprintf(command_line, sizeof(command_line),
			"%s -d %s -c %s", CIFSD_SHARE, name, CIFSD_CONF);
	smbmgr_info("(%s)", command_line);

	g_spawn_command_line_sync(command_line, NULL, NULL, &child_status, &error);
	if (error != NULL)
		smbmgr_err("spawning 'cifsshareadd -d' failed: %s", error->message);

	pthread_mutex_unlock(&cifsd_lock);
}

void cifsd_cleanup()
{
	unlink(CIFSD_CONF);
	smbmgr_info("deleted %s", CIFSD_CONF);
}

