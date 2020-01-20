int cifsd_start(const char *tcp_port);
int cifsd_stop();
int cifsd_user_add(const char *id, const char *pw);
int cifsd_user_delete(const char *id);
void cifsd_share_add(const char *name, const char *path);
void cifsd_share_delete(const char *name);
void cifsd_cleanup();

