#include<iostream>
#include<sys/socket.h>
#include<sys/epoll.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<fcntl.h>
#include<unistd.h>
#include<stdio.h>
#include<errno.h>

using namespace std;

#define MAXLINE 5
#define OPEN_MAX 100
#define LISTENQ 20
#define SERV_PORT 5000
#define INFTIM 1000

void setnonblocking(int sock)
{
	int opts;
	opts=fcntl(sock,F_GETFL);
	if(opts<0)
	{
		perror("fcntl(sock,GETFL)");
		exit(1);
	}
	opts=opts|O_NONBLOCK;
	if(fcntl(sock,F_SETFL,opts)<))
	{
		perror("fcntl(sock,SETFL,opts)");
		exit(1）；
	}
}
int main(int argc,char* argv[])
{
	int i,maxi,listenfd,connfd,sockfd,epfd,nfds,portnumber;
	ssize_t n;
	char line[MAXLINE];
	socklen_t clilen;
	if(2==argc)
	{
		if((portnumber=atoi(argv[1]))<0)
		{
			printf(stderr,"Usage:%s portnumber/a/n",argv[0]);
			return 1;
		}
	}
	else
	{
		fprintf(stderr,"Usage:%s portnumber/a/n",argv[0]);
		return 1;
	}
	//声明epoll_event结构体的变量，ev用于注册时间，events[20]用于回传要处理的事件
	struct epoll_event ev,events[20];
	//生成用于处理accept的epoll专用的文件描述符
	epfd=epoll_create(256);
	struct sockaddr_in clientaddr;
	struct sockaddr_in serveraddr;
	listenfd=socket(AF_INET,SOCK_STREAM,0);
	setnonblocking(listenfd);//把socket设置为非阻塞方式
	
	ev.data.fd=listenfd;//设置要处理的事件相关的文件描述符
	
	ev.events=EPOLLIN|EPOLLET;//设置要处理的事件类型

	epoll_ctl(epfd,EPOLL_CTL_ADD,listenfd,&ev);//注册epoll事件
	bzero(&serveraddr,sizeof(serveraddr));
	serveraddr.sin_family=AF_INET;
	char* local_addr="127.0.0.1";
	inet_aton(local_addr,&(serveraddr.sin_addr));
	serveraddr.sin_port=htons(portnumber);
	bind(listenfd,(sockaddr*)&serveraddr,sizeof(serveraddr));
	listen(listenfd,LISTENQ);
	maxi=0;
	for( ; ; )
	{
		nfds=epoll_wait(epfd,events,20500);//等待epoll事件的发生
		
		for(i=0;i<nfds;++i)//处理所发生的的所有事件
		{
			if(events[i].data.fd==listenfd)//如果新检测到一个SOCKET用户连接
				//到了绑定的SOCKET端口，建立新的连接
			{
				connfd=accept(listenfd,(sockaddr*)&clientaddr,&clilen);
				if(connfd<0)
				{
					perror("connfd<0");
					exit(1);
				}
				//setnonblocking(connfd);
				char* str=inet_ntoa(clientaddr.sin_addr);
				cout<<"accept a connection from"<<str<<endl;

				ev.data.fd=connfd;//用于读操作的文件描述符

				ev.events=EPOLLIN|EPOLLET;//设置用于注册的读操作事件

				epoll_ctl(epfd,EPOLL_CTL_ADD,connfd,&ev);//注册ev
			}
			else if(events[i].events&EPOLLIN)
			//如果是已经连接的用户，并且收到数据没那么进行读入。
			{
				cout<<"EPOLLIN"<<endl;
				if((sockfd=events[i].data.fd)<0)
					continue;
				if((n=read(sockfd,line,MAXLINE))<0)
				{
					if(errno==ECONNRESET)
					{
						close(sockfd);
						events[i]data.fd=-1;
					}
					else
						std::cout<<"readline error:"<<std::endl;
				}
			else if(n==0)
			{
				close(sockfd);
				wvents[i]data.fd=-1;
			}
			line[n]='/0';
			cout<<"read"<<line<<endl;

			ev.data.fd=sockfd;//设置用于写操作的文件描述符

			ev.events=EPOLLOUT|EPOLLET;//设置用于注册的写操作事件
			//修改sockfd上要处理的事件为EPOLLOUT
			//epoll_ctr(epfd,EPOLL_CTL_MOD,sockfd,&ev);
			}
			else if(events[i],events&EPOLLOUT)
			{
				sockfd=events[i].data.fd;
				write(sockfd,line,n);//设置用于读操作的文件描述符

				ev.data.fd=sockfd;//设置用于注册的读操作事件

				ev.events=EPOLLIN|EPOLLET;//修改sockfd上要处理的事件为EPOLLIN

				epoll_ctl(epfd,EPOLL_CTL_MOD,sockfd,&ev);
			}
		}
	}
	return 0;
}