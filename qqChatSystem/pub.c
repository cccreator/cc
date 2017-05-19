/*
 * pub.c
 *
 *  Created on: 2013年12月27日
 *      Author: zhujy
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <fcntl.h>
#include "work.h"
#include "pub.h"


void setdaemon()
{
	pid_t pid, sid;
	pid = fork();
	if (pid < 0)
	{
		printf("fork failed %s\n", strerror(errno));
		exit (EXIT_FAILURE);
		;
	}
	if (pid > 0)
	{
		exit (EXIT_SUCCESS);
	}

	if ((sid = setsid()) < 0)
	{
		printf("setsid failed %s\n", strerror(errno));
		exit (EXIT_FAILURE);
	}

	/*
	 if (chdir("/") < 0)
	 {
	 printf("chdir failed %s\n", strerror(errno));
	 exit(EXIT_FAILURE);
	 }
	 umask(0);
	 close(STDIN_FILENO);
	 close(STDOUT_FILENO);
	 close(STDERR_FILENO);
	 */
}

void catch_Signal(int Sign)
{
	switch (Sign)
	{
	case SIGINT:
		printf("signal SIGINT\n");
		break;
	}
}

int signal1(int signo, void (*func)(int))
{
	struct sigaction act, oact;
	act.sa_handler = func;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	return sigaction(signo, &act, &oact);
}

int hex2dec(const char hex) //将16进制的字符转化为十进制的整数，例如：'a'转化为整数10,‘B’转化为整数11
{
	switch (hex)
	{
	case '0':
		return 0;
	case '1':
		return 1;
	case '2':
		return 2;
	case '3':
		return 3;
	case '4':
		return 4;
	case '5':
		return 5;
	case '6':
		return 6;
	case '7':
		return 7;
	case '8':
		return 8;
	case '9':
		return 9;
	case 'a':
		return 10;
	case 'A':
		return 10;
	case 'b':
		return 11;
	case 'B':
		return 11;
	case 'c':
		return 12;
	case 'C':
		return 12;
	case 'd':
		return 13;
	case 'D':
		return 13;
	case 'e':
		return 14;
	case 'E':
		return 14;
	case 'f':
		return 15;
	case 'F':
		return 15;
	default:
		return -1;
	}
}


//将两位16进制的字符串转化为十进制的unsigned char，例如：'10'转化为16,‘1A'转化为17
unsigned char hexstr2dec(const char *hex) 
{
	return hex2dec(hex[0]) * 16 + hex2dec(hex[1]);
}

//将HTTP GET请求中的转义符号转化为标准字符,注意，空格被转义为'+'号
void httpstr2stdstr(const char *httpstr, char *stdstr)
{
	int index = 0;
	int i;
	for (i = 0; i < strlen(httpstr); i++)
	{
		if (httpstr[i] == '%')
		{
			stdstr[index] = hexstr2dec(&httpstr[i + 1]);
			i += 2;
		} else
		{
			stdstr[index] = httpstr[i];
		}
		index++;
	}
}

const char *getfiletype(const char *filename) //根据扩展名返回文件类型描述
{
	////////////得到文件扩展名///////////////////
	int len = strlen(filename);
	int i;
	char sExt[32];
	memset(sExt, 0, sizeof(sExt));
	for (i = 0; i < len; i++)
	{
		if (filename[i] == '.')
		{
			strncpy(sExt, &filename[i + 1], sizeof(sExt));
			break;
		}
	}

	////////根据扩展名返回相应描述///////////////////

	if (strncmp(sExt, "bmp", 3) == 0)
		return "image/bmp";

	if (strncmp(sExt, "gif", 3) == 0)
		return "image/gif";

	if (strncmp(sExt, "ico", 3) == 0)
		return "image/x-icon";

	if (strncmp(sExt, "jpg", 3) == 0)
		return "image/jpeg";

	if (strncmp(sExt, "avi", 3) == 0)
		return "video/avi";

	if (strncmp(sExt, "css", 3) == 0)
		return "text/css";

	if (strncmp(sExt, "dll", 3) == 0)
		return "application/x-msdownload";

	if (strncmp(sExt, "exe", 3) == 0)
		return "application/x-msdownload";

	if (strncmp(sExt, "dtd", 3) == 0)
		return "text/xml";

	if (strncmp(sExt, "mp3", 3) == 0)
		return "audio/mp3";

	if (strncmp(sExt, "mpg", 3) == 0)
		return "video/mpg";

	if (strncmp(sExt, "png", 3) == 0)
		return "image/png";

	if (strncmp(sExt, "ppt", 3) == 0)
		return "application/vnd.ms-powerpoint";

	if (strncmp(sExt, "xls", 3) == 0)
		return "application/vnd.ms-excel";

	if (strncmp(sExt, "doc", 3) == 0)
		return "application/msword";

	if (strncmp(sExt, "mp4", 3) == 0)
		return "video/mpeg4";

	if (strncmp(sExt, "ppt", 3) == 0)
		return "application/x-ppt";

	if (strncmp(sExt, "wma", 3) == 0)
		return "audio/x-ms-wma";

	if (strncmp(sExt, "wmv", 3) == 0)
		return "video/x-ms-wmv";

	return "text/html";
}

int getfilecontent(const char *filename, char **buf) //得到文件内容
{
	struct stat t;
	memset(&t, 0, sizeof(t));
	FILE *fd = fopen(filename, "rb");//从只读方式打开参数filename指定的文件
	if (fd != NULL)
	{
		stat(filename, &t);
		*buf = malloc(t.st_size);//根据文件大小，动态分配内存buf
		fread(*buf, t.st_size, 1, fd);//将文件读取到buf
		fclose(fd);
		return t.st_size;
	} else
	{
		printf("open %s failed %s\n", filename, strerror(errno));
		return 0;
	}
}

int socket_create(int port)//根据参数port，建立server端socket
{
	int st = socket(AF_INET, SOCK_STREAM, 0);//建立TCP的socket描述符
	if (st == -1)
	{
		printf("socket failed %s\n", strerror(errno));
		return 0;
	}
	int on = 1;
	if (setsockopt(st, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1)
	{
		printf("setsockopt failed %s\n", strerror(errno));
		return 0;
	}
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(st, (struct sockaddr *) &addr, sizeof(addr)) == -1)
	{
		printf("bind failed %s\n", strerror(errno));
		return 0;
	}
	if (listen(st, 100) == -1)
	{
		printf("listen failed %s\n", strerror(errno));
		return 0;
	}
	printf("listen %d success\n", port);
	return st;//返回listen的socket描述符
}

void sockaddr_toa(const struct sockaddr_in *addr, char *IPAddr)//将struct sockaddr_in转化为IP地址字符串
{
	unsigned char *p = (unsigned char *)&(addr->sin_addr.s_addr);
	sprintf(IPAddr, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
}

void socket_accept(int st)
{
	pthread_t thr_d;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);//设置线程为可分离状态
	int client_st = 0;
	struct sockaddr_in client_addr;
	socklen_t len = sizeof(client_addr);
	while (1)//循环执行accept
	{
		memset(&client_addr, 0, sizeof(client_addr));
		//accept函数阻塞，知道有client端连接到达，或者accept错误返回
		client_st = accept(st, (struct sockaddr *)&client_addr, &len);

		if (client_st == -1)
		{
			printf("accept failed %s\n", strerror(errno));
			break;//accept错误，循环break
		} else
		{
			char sIP[32];
			memset(sIP, 0, sizeof(sIP));
			sockaddr_toa(&client_addr, sIP);
			printf("accept by %s\n", sIP);
			int *tmp = malloc(sizeof(int));
			*tmp = client_st;
			{
				//将来自client端的socket做为参数，启动一个可分离线程
				pthread_create(&thr_d, &attr, socket_contr, tmp);
			}
		}
	}
}


