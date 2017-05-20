//≤Â»Î≈≈–Ú∑®
#include<iostream>
int main()
{
	using namespace std;
	int a[6]={53,27,36,15,69,42};
	int i,temp,p;
	for(i=1;i<6;i++)
	{
		temp=a[i];
		p=i-1;
		while(p<=0&&temp<a[p])
		{
			a[p+1]=a[p];
			p--;
		}
		a[p+1]=temp;
	}
}
