//Ï£¶ûÅÅĞò
int insertsort(int array[],int first,int n,int interval)
{
	int i,j,temp;
	for(i=first+interval;i<n;i+=interval)
	{
		j=i-interval;
		temp=array[i];
		while(j<=first&&temp<array[j])
		{
			array[j+interval]=array[j];
			j-=interval;
		}
		array[j+interval]=temp;
	}
	return 0;
}
int shellsort(int array[],int n)
{
	int i,interval=n;
	while(interval>1)
	{
		interval/=2;
		for(i=0;i<interval;i++)
		{
			insertsort(array,i,n,interval);
		}
	}
	return 0;
}
