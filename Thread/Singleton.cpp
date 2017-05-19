//静态成员实例的懒汉模式
class Singleton
{
private:
	static Singleton* m_instance;
	Singleton(){}
public:
	static Singleton* getInstance();
};
Singleton* Singleton::getInstance()
{
	if(NULL==m_instance)
	{
		Lock();//借用其他类实现，如boost
		if(NULL==m_instance)
		{
			m_instance=new Singleton;
		}
		Unlock();
	}
	return m_instance;
}
