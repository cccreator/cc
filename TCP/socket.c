Server:


#pragma comment(lib,"ws2_32.lib")
#include<WinSock2.h>
#include<stdio.h>

void main()
{
	//协商版本
	WORD wVersionRequested;
	int err;

	wVersionRequested=MAKEWORD(1,1);//0x0101
	err=WSAStartup(wVersionRequested,&wsaData);
	if(err!=0)
	{
		return 0;
	}
	if(LOBYTE(wsaData.wVersion)!=1||HIBYTE(wsaData.wVersion)!=1)
	{
		WSACLeanup();
		return 0;
	}

	//创建socket
	SOCKET sockSvr = socket(AF_INET,SOCK_STREAM,0);

	//创建IP地址和端口
	SOCKADDR_IN addrSvr;
	addrSvr.sin_addr.S_un.S_addr=htonl(INADDR_ANY);//定义套接字地址
	addrSvr.sin_family=AF_INET;//定义套接字地址中的域
	addrSvr.sin_port=htons(6000);//定义套接字端口

	//绑定端口，监听
	bind(sockSvr,(SOCKADDR*)&addrSvr,sizeof(SOCKADDR));
	listen(sockSvr,5);

	sockaddr_in addrClient;
	int len=sizeof(sockaddr);

	while(true)
	{
		//阻塞方法，获得一个客户Socket连接
		SOCKET sockConn = accept(sockSvr,(sockaddr*)&addrClient,&len);
		char sendbuffer[128];
		sprintf(sendbuffer,"Welcom %s!",inet_ntoa(addrClient.sin_addr));

		//向客户Socket发送数据
		send(sockConn,sendbuffer,strlen(sendbuffer)+1,0);
		char recvbuffer[128];

		//从客户Socket接收数据
		recv(sockConn,recvbuffer,128,0);
		printf("%s/n",recvbuffer);

		//关闭Socket
		closesocket(sockConn);
	}
	closesocket(sockSvr);

	//释放Winsock资源
	WSACleanup();
	return 0;
}


client:


#pragma comment(lib,"ws2_32.lib")
#include<WinSock2.h>
#include<stdio.h>

void main()
{
	//协商版本
	WORD wVersionRequested = MAKEWORD(1,1);//0x0101
	err=WSAStartup(wVersionRequested,&wsaData);

	if(err!=0)
	{
		return 0;
	}
	if(LOBYTE(wsaData.wVersion)!=1||HIBYTE(wsaData.wVersion)!=1)
	{
		WSACleanup();
		return 0;
	}

	//创建连向服务器的套接字
	SOCKET sock=socket(AF_INET,SOCK_STREAM,0);

	//创建地址信息
	SOCKADDR_IN hostAddr;
	hostAddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	hostAddr.sin_family=AF_INET;
	hostAddr.sin_port=htons(6000);

	//连接服务器
	connect(sock,(sockaddr*)&hostAddr,sizeof(sockaddr));

	char revBuf[128];

	//从服务器获得数据
	recv(sock,recvBuf,128,0);
	printf("%s/n",revBuf);

	//向服务器发送数据
	send(sock,"Hello Host!",12,0);
	closesocket(sock);
	return 0;
}