#include<unistd.h>
#include<pthread.h>

#define CONSUMERS_COUNT 2
#deifne PRODUCERS_COUNT 1

pthread_mutex_t g_mutex;
pthread_cond_t g_cond;

pthread_t g_mutex[CONSUMERS_COUNT+PRODUCERS_COUNT];
int share_variable=0;

void* consumer(void* arg)
{
	int mum=(int)arg;
	while(1)
	{
		pthread_mutex_lock(&g_mutex);
		while(share_variable==0)
		{
			printf("consumer %d begin wait a condition...\n",num);
			pthread_cond_wait(&g_cond,&g_mutex);
		}
		printf("consumer %d end wait a condition...\n",num);
		printf("consumer %d begin consume product\n",num);
		--share_variable;
		pthread_mutex_unlock(&g_mutex);
		sleep(1);
	}
	return NULL;
}
void* producer(void* arg)
{
	int num=(int)arg;
	while(1)
	{
		pthread_mutex_lock(&g_mutex);
		ptintf("producer %d begin produce product...\n",num);
		++share_variable;
		pringt("producer %d end produce product...\n",num);
		pthread_cond_signal(&g_cond);
		printf("producer %d notified consumer by condition variable...\n",num);
		pthread_mutex_unlock(&g_mutex);
		sleep(5);
	}
	return 1;
}
int main(void)
{
	pthread_mutex_init(&g_mutex,NULL);
	pthread_cond_init(&g_cond,NULL);

	for(int i=0;i<CONSUMERS_COUNT;++i)
	{
		pthread_create(&g_thread[i],NULL,consumer,(void*)i);
	}
	sleep(1);
	for(int i=0;i<PRODUCERS_COUNT;++i)
	{
		pthread_create(&g_thread[i];NULL,producer,(void*)i);
	}
	for(int i=0;i<CONSUMERS_COUNT+PRODUCERS_COUNT;++i)
	{
		pthread_join(g_thread[i],NULL);
	}
	pthread_mutex_destroy(&g_mutex);
	pthread_cond_destroy(&g_cond);
}
