#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<string.h>
#include<pthread.h>
#include<semaphore.h>
void* thread_function(void* arg);
sem_t bin_sem;
#define WORK_SIZE 1024
char work_area[WORK_SIZE];
int main()
{
	int res;
	pthread_t a_thread;
	void* thread_result;
	res=sem_init(&bin_sem,0,0);
	res=pread_create(&a_thread,NULL,thread_function,NULL);
	printf("请输入要传送的信息，输入'end'推出\n");
	while(strncmp("end",work_area,3)!=0)
	{
		fgets(work_area,WORK_SIZE,stdin);
		sem_post(&bin_sem);
	}
	printf("\n等待线程结束..");
	res=pthread_join(a_thread,&thread_result);
	printf("线程结束\n");
	sem_destroy(&bin_sem);
	exit(EXIT_SUCCESS);
}
void* thread_function(void* arg)
{
	sem_wait(&bin_sem);
	while(strncmp("end",work_area,3)!=0)
	{
		printf("收到%d个字符\n",strlen(work_area)-1);
		sem_wait(&bin_sem);
	}
	pthread_exit(NULL);
}
