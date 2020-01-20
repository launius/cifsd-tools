
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <smbmgr.h>

#if 1
int main()
{
	int opt;

	while(1) {
		printf("== smb-manager test menu ==\n");
		printf("1. smbmgr_start\n");
		printf("2. smbmgr_disk_add\n");
		printf("3. smbmgr_disk_delete\n");
		printf("4. smbmgr_stop\n");
		printf("9. exit\n");
		printf("input: ");

		assert(scanf("%d", &opt) > 0);
		switch(opt) {
			case 1:
				printf("calling smbmgr_start..\n");
				smbmgr_start();
				break;
			case 2:
				printf("calling smbmgr_disk_add..\n");
				smbmgr_disk_add();
				break;
			case 3:
				printf("calling smbmgr_disk_delete..\n");
				smbmgr_disk_delete();
				break;
			case 4:
				printf("calling smbmgr_stop..\n");
				smbmgr_stop();
				break;
			case 9:
				_exit(0);
				break;
			default:
				printf("input error!\n");
				break;
		}
	}
}
#endif

#if 0
void sig_handler(int signo)
{
	smbmgr_disk_delete();

	if (smbmgr_stop() != IPC_STATE_OK)
		printf("smbmgr stop fail\n");
	else
		printf("smbmgr stop success\n");

	_exit(0);
}

int main()
{
	int rc;
	pid_t pid;

	signal(SIGTERM, (void *)sig_handler);

	rc = smbmgr_start();
	if (rc != IPC_STATE_OK)
		printf("smbmgr start fail\n");
	else
		printf("smbmgr start success\n");

	smbmgr_disk_add();

	if ((pid = fork()) < 0) {
		printf("fork() failed\n");
		return 1;
	} else if (pid > 0)
		_exit(0);

	while (1)
		sleep(10);

	return 0;
}
#endif

