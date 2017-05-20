//ц╟ещеепР
bubbleSort(int arr[],int length)
{
	for(int i=0;i<length;++i)
	{
		for(int j=0;j<length-i-1;++j)
		{
			if(arr[j]<arr[j+1])
			{
				int temp=arr[j];
				arr[j]=arr[j+1];
				arr[j+1]=temp;
			}
		}
	}
}
