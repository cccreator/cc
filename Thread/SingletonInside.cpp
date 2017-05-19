//内部静态实例的懒汉模式
class SingletonInside
{
private:
	SingletonInside(){}
public:
	static SingletonInside* getInstance()
	{
		Lock();// not needed after C++0x
		static SingletonInside instance;
		Unlock();// not needed after C++0x
		return instance;
	}
};
