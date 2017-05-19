#include<stdio.h>
#include<unistd.h>
#include<pthread.h>
#include<string.h>
#include<stdlib.h>
void* thread_function(void* arg);
char message[]="THREAD_TEST";
int main()
{
	int res;
	pthread_t a_thread;
	void* thread_result;//用来接收线程结束时的返回值，thread_result本身就是一个指针
	res=pthread_create(&a_thread,NULL,thread_function,(void*)message);
	if(res!=0)
	{
		perror("pthread_create failed");
		exit(EXIT_FAILURE);
	}
	printf("等待线程结束...\n");
	res=pthread_join(a_thread,&thread_result);//等待线程结束，注意&
	if(res!=0)
	{
		perror("pthread_join failed");
		exit(EXIT_FAILURE);
	}
	printf("线程已结束，返回值: %s\n",(char*)thread_result);//输出线程返回的消息
	printf("Message的值为： %s\n",message);//输出公用的内存空间的值
	exit(SUCCESS);
}
void* thread_function(void* arg)
{
	printf("线程在运行，参数为: %s\n",(char*)arg);
	sleep(3);
	strcpy(message,"线程修改");//修改公用的内存空间的值
	pthread_exit("线程执行完毕");//线程结束，返回线程执行完毕
}