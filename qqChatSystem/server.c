/*
 * server.c
 *
 *  Created on: 2013年12月27日
 *      Author: zhujy
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include "pub.h"
#include "myoracle.h"

int main(int arg, char *args[])
{	
	if (arg < 2)//如果没有参数，main函数返回
	{
		printf("usage:myserver port\n");
		return EXIT_FAILURE;
	}

	int iport = atoi(args[1]);//将第一个参数转化为整数
	if (iport == 0)
	{
		printf("port %d is invalid\n", iport);
		return EXIT_FAILURE;
	}
	
	if (sql_connect("dbuser1", "dbuser1", "orcl") == -1)//连接到数据库
		return EXIT_FAILURE;	
	
	int st = socket_create(iport);//建立socket
	if (st == 0)
		return EXIT_FAILURE;
	
	printf("myhttp is begin\n");
	setdaemon();//设置进程为daemon状态
	signal1(SIGINT, catch_Signal);	//捕捉SIGINT信号	
	socket_accept(st);
	close(st);
	sql_disconnect();
	printf("myhttp is end\n");
	return EXIT_SUCCESS;
}

