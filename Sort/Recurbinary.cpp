//二分法查找
#include<iostream>
using namespace std;
int recurbinary(int[] a,int T)
{
	int mid,low,high;
	low=0;
	high=a.length-1;
	while(low<=high)
	{
		mid=(low+high)/2;
		if(a[mid]<T)
		{
			low=mid+1;
		}
		else if(a[mid]>T)
		{
			high=mid-1;
		}
		else
		{
			return mid;
		}
	}
	return -1;
}
