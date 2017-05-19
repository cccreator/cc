#include<stdio.h>
#include<unistd.h>
#include<pthread.h>
#include<string.h>
#include<stdlib.h>
#include<semaphore.h>
void* thread_function(void* arg);//定义线程函数原型
pthread_mutex_t work_mutex;//定义互斥量
#define WORK_SIZE 1024;
char work_area[WORK_SIZE];//定义公用的内存空间
int time_to_exit=1;//用于控制循环
int main()
{
	int res;
	pthread_t a_thread;
	void* thread_result;
	res=pthread_mutex_init(work_mutex,NULL);//创建并初始化互斥量
	if(res!=0)
	{
		perror("pthread_mutex_init failed");
		exit(EXIT_FAILURE);
	}
	res=pthread_create(&a_thread,NULL,thread_function,NULL);
	if(res!=0)
	{
		perror("pthread_create failed");
		exit(EXIT_FAILURE);
	}
	pthread_mutex_lock(&work_mutex);//把互斥量mutex加锁，以确保同一时间只有该线程可以访问word_area中的数据
	printf("请输入要传送的信息，输入'end'退出\n");
	while(time_to_exit)
	{
		fgets(work_area,WORK_SIZE,stdin);//接收输入信息
		pthread_mutex_unlock(&work_mutex);//把互斥量解锁，让其他的线程可以访问work_area中的数据
		while(1)
		{
			pthread_mutex_lock(&work_mutex);
			if(work_area[0]!='\0')//判断公共内存空间是否为空
			{
				pthread_mutex_unlock(&work_mutex);
				sleep(1);
			}
			else
			{
				break;
			}
		}
	}
	pthread_mutex_unlock(&work_mutex);
	printf("\n 等待线程结束...\n");
	res=pthread_join(a_thread,&thread_result);
	printf("线程结束\n");
	pthread_mutex_destroy(&work_mutex);//清除互斥量
	exit(EXIT_SUCCESS);
}
void* thread_function(void* arg)
{
	sleep(1);
	pthread_mutex_lock(&work_mutex);
	while(strncmp("end",work_area,3)!=0)//判断收到的信息是否为end
	{
		printf("收到%d个字符\n",strlen(work_area)-1);
		work_area[0]='\0';//将公共空间清除
		pthread_mutex_lock(&work_mutex);
		sleep(1);
		pthread_mutex_lock(&work_mutex);
		while(work_area[0]=='\0')//判断公共空间是否为空
		{
			pthread_mutex_unlock(&work_mutex);
			sleep(1);
			pthread_mutex_lock(&work_mutex);
		}
	}
	time_to_exit=0;//将循环结束标志置为0
	work_area[0]='\0';//清除公共空间
	pthread_mutex_unlock(&work_mutex);
	pthread_exit(0);//结束线程
}