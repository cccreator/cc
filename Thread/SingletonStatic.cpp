//饿汉模式
class SingletonStatic
{
private:
	static const SingletonStatic* m_instance;
	SingletonStatic(){}
public:
	static const SingletonStatic* getInstance()
	{
		return m_instance;
	}
};
//外部初始化 before invoke main
const SingletonStatic* SingletonStatic::m_instance=new SingletonStatic;