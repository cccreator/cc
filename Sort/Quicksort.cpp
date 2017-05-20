//©ЛкыеепР
int quicksort(vector<int> &v,int left,int right)
{
	if(left<right)
	{
		int temp=v[left];
		int low=left;
		int high=right;
		while(low<high)
		{
			while(low<high&&temp<v[high])
			{
				high--;
			}
			v[low]=v[high];
			while(low<high&&temp>v[low])
			{
				low++;
			}
			v[high]=v[low];
		}
		v[low]=temp;
		quicksort(v,left,low-1);
		quicksort(v,low+1,right);
	}
}
