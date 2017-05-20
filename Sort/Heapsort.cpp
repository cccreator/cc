#include<iostream>
using namespace std;
void swap(int a[],int i,int j)
{
	int temp=a[i];
	a[i]=a[j];
	a[j]=temp;
}
void HeapAdjust(int* a,int i,int size)
{
	int left=2*i;
	int right=2*i+1;
	int max=i;
	if(left<=size&&a[left]>a[max])
		max=left;
	if(right<=size&&a[right]>a[max])
		max=right;
	if(max!=i)
	{
		swap(a,i,max);
		HeapAdjust(a,max,size);
	}
}
void BuildHeap(int a[],int size)
{
	for(int i=size/2;i>=1;i--)
	{
		HeapAdjust(a,i,size);
	}
}
void HeapSort(int a[],int size)
{
	BuildHeap(a,size);
	for(int i=size;i>=2;i--)
	{
		swap(a,1,i);
		size--;
		HeapAdjust(a,1,size);
	}
}
void print(int a[],int size)
{
	for(int i=1;i<size;i++)
		cout<<a[i]<<" ";
	cout<<a[size]<<endl;
}
int main()
{
	int a[7]={0,4,6,1,5,3,2};
	cout<<"ÅÅÐòÇ°£º "<<endl;
	print(a,6);
	HeapSort(a,6);
	cout<<"ÅÅÐòºó: "<<endl;
	print(a,6);
	system("pause");
	return 0;
}
