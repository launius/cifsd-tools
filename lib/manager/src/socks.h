#define _GNU_SOURCE

#include <sys/socket.h>

int sock_get_server(const char *path);
int sock_set_client(int fd);
int sock_get_client_cred(int fd, struct ucred *cred);
int sock_cleanup();

