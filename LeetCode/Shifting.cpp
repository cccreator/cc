#include<iostream>
using namespace std;
int main()
    {
    unsigned long long n,a,b,c,d;
    char ch;
    while(cin>>a>>ch>>b>>ch>>c>>ch>>d)
        {
        cin>>n;
        unsigned long long res=0;
        res=(a<<24)+(b<<16)+(c<<8)+d;
        a=n>>24;
        b=(n>>16)&255;
        c=(n>>8)&255;
        d=n&255;
        cout<<res<<endl;
        cout<<a<<"."<<b<<"."<<c<<"."<<d<<endl;
    }
    return 0;
}