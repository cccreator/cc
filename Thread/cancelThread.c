#include<stdio.h>
#include<unistd.h>
#include<pthread.h>
#include<stdlib.h>
void* thread_function(void* arg);
int main()
{
	int res;
	pthread_t a_thread;
	void* thread_result;
	res=pthread_create(&a_thread,NULL,thread_function,NULL);
	if(res!=0)
	{
		perror("pthread_create failed");
		exit(EXIT_FAILURE);
	}
	sleep(3);
	printf("取消线程...\n");
	res=pthread_cancel(a_thread);//发送取消线程请求
	if(res!=0)
	{
		perror("pthread_cancel failed");
		exit(EXIT_FAILURE);
	}
	printf("等待线程结束...\n");
	res=pthread_join(a_thread,&thread_result);//等待线程结束
	if(res!=0)
	{
		perror("pthread_join failed");
		exit(EXIT_FAILURE);
	}
	exit(EXIT_SUCCESS);
}
void* thread_function(void* arg)
{
	int i,res;
	res=pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,NULL);//允许线程接收取消线程请求
	if(res!=0)
	{
		perror("pthread_setcancelstate failed");
		exit(EXIT_FAILURE);
	}
	res=pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED,NULL);//设置取消线程类型，采取一些行动后再结束
	if(res!=0)
	{
		perror("pthread_setcanceltype failed");
		exit(EXIT_FAILURE);
	}
	printf("线程函数正在运行(%d)...\n");
	for(i=0;i<10;i++)
	{
		printf("线程函数正在运行(%d)...\n");
		sleep(1);
	}
	pthread_exit(0);
}