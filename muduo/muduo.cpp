#include<iostream>  
#include<map>  
#include<string>  
#include<vector>  
#include<utility>  
#include<set>  
#include<deque>  
#include<algorithm>  
#include<boost/any.hpp>  
#include<boost/enable_shared_from_this.hpp>  
#include<boost/noncopyable.hpp>  
#include<boost/scoped_ptr.hpp>  
#include<boost/shared_ptr.hpp>  
#include<boost/weak_ptr.hpp>  
#include<boost/function.hpp>  
#include<boost/static_assert.hpp>  
#include<boost/bind.hpp>  
#include<boost/foreach.hpp>  
#include<boost/ptr_container/ptr_vector.hpp>  
#include<errno.h>  
#include<fcntl.h>  
#include<stdio.h>  
#include<strings.h>  
#include<unistd.h>  
#include<endian.h>  
#include<assert.h>  
#include<stdio.h>  
#include<stdlib.h>  
#include<string.h>  
#include<pthread.h>  
#include<unistd.h>  
#include<poll.h>  
#include<errno.h>  
#include<signal.h>  
#include<stdint.h>  
#include<arpa/inet.h>  
#include<netinet/tcp.h>  
#include<netinet/in.h>  
#include<sys/timerfd.h>  
#include<sys/syscall.h>  
#include<sys/time.h>  
#include<sys/eventfd.h>  
#include<sys/types.h>  
#include<sys/socket.h>  
#include<sys/epoll.h>  
using namespace std;  
using namespace boost;  
# define UINTPTR_MAX       (4294967295U)//一个无符号大数  
/* 
*互斥量 
*/  
class Mutex:noncopyable{  
    public:  
        Mutex(){  
            pthread_mutex_init(&mutex,NULL);  
        }  
        void lock(){  
            pthread_mutex_lock(&mutex);  
        }  
        void unlock(){  
            pthread_mutex_unlock(&mutex);  
        }  
        pthread_mutex_t& get(){  
            return mutex;  
        }  
    private:  
        pthread_mutex_t mutex;  
};  
/* 
*互斥量RAII 
*/  
class MutexLockGuard:noncopyable{  
    public:  
        explicit MutexLockGuard(Mutex& mutex):mutex_(mutex){  
            mutex_.lock();  
        }  
        ~MutexLockGuard(){  
            mutex_.unlock();  
        }  
    private:  
        Mutex& mutex_;  
};  
/* 
*条件变量 
*/  
class Condition:noncopyable{  
    public:  
        explicit Condition(Mutex& mutex):mutex_(mutex){  
            pthread_cond_init(&pcond_,NULL);  
        }  
        ~Condition(){  
            pthread_cond_destroy(&pcond_);  
        }  
        void wait(){  
            pthread_cond_wait(&pcond_,&mutex_.get());  
        }  
        void notify(){  
            pthread_cond_signal(&pcond_);  
        }  
        void notifyALL(){  
            pthread_cond_broadcast(&pcond_);  
        }  
    private:  
        Mutex& mutex_;  
        pthread_cond_t pcond_;  
};  
/* 
*倒计时闩 
*/  
class CountDownLatch{  
    public:  
        CountDownLatch(int count):mutex_(),condition_(mutex_),count_(count){}  
        void wait(){  
            MutexLockGuard lock(mutex_);  
            while(count_>0)  
                condition_.wait();  
        }  
        void countDown(){  
            MutexLockGuard lock(mutex_);  
            --count_;  
            if(count_==0)  
                condition_.notifyALL();  
        }  
    private:  
        mutable Mutex mutex_;  
        Condition condition_;  
        int count_;  
};  
/* 
 *线程类Thread 
 */  
__thread pid_t t_cacheTid=0;//线程私有数据线程ID避免通过系统调用获得ID  
class Thread:noncopyable{  
    public:  
        typedef function<void()> ThreadFunc;//线程需要执行工作函数  
        explicit Thread(const ThreadFunc& a,const string& name=string()):started_(false),  
            joinded_(false),pthreadID_(0),tid_(new pid_t(0)),func_(a),name_(name){  
            }  
        ~Thread(){  
            if(started_&&!joinded_){  
                pthread_detach(pthreadID_);//分离线程  
            }  
        }  
        void start();  
        /* 
        { 
            assert(!started_); 
            started_=true; 
            if(pthread_create(&pthreadID_,NULL,&startThread,NULL)){ 
                started_=false; 
                abort();//终止进程刷新缓冲区 
            } 
        } 
        *///###1###使用此处会出错详见http://cboard.cprogramming.com/cplusplus-programming/113981-passing-class-member-function-pthread_create.html  
        void join(){//等待线程执行完工作函数  
            assert(started_);  
            assert(!joinded_);  
            joinded_=true;  
            pthread_join(pthreadID_,NULL);  
        }  
        pid_t tid() const{  
            if(t_cacheTid==0){//如果没有缓存t_cacheTid则获取线程ID否则直接通过线程私有数据返回ID减少系统调用  
                t_cacheTid=syscall(SYS_gettid);  
            }  
            return t_cacheTid;  
        }  
        const string& name() const{  
            return name_;  
        }  
        //void* startThread(void* arg){//###1###  
        void startThread(){  
            func_();  
        }  
    private:  
        bool started_;  
        bool joinded_;  
        pthread_t pthreadID_;  
        shared_ptr<pid_t> tid_;  
        ThreadFunc func_;  
        string name_;  
};  
void* threadFun(void* arg){//采用间接层执行工作函数  
    Thread* thread=static_cast<Thread*>(arg);  
    thread->startThread();  
    return NULL;  
}  
void Thread::start(){  
    assert(!started_);  
    started_=true;  
    if(pthread_create(&pthreadID_,NULL,threadFun,this)){  
        started_=false;  
        abort();//终止进程刷新缓冲区  
    }  
}  
  
/* 
 * 线程局部数据TSD 
 */  
template<typename T>  
class ThreadLocal:noncopyable{  
    public:  
        ThreadLocal(){  
            pthread_key_create(&pkey_,&destructor);//每个线程会设定自己的pkey_并在pthread_key_delete执行destructor操作  
        }  
        ~ThreadLocal(){  
            pthread_key_delete(pkey_);//执行destructor操作  
        }  
        T& value(){//采用单件模式，此处不会跨线程使用故不存在非线程安全的singleton问题  
            T* perThreadValue=static_cast<T*>(pthread_getspecific(pkey_));  
            if(!perThreadValue){  
                T* newObj=new T();  
                pthread_setspecific(pkey_,newObj);  
                perThreadValue=newObj;  
            }  
            return *perThreadValue;  
        }  
    private:  
        static void destructor(void* x){//清除私有数据  
            T* obj=static_cast<T*>(x);  
            delete obj;  
        }  
    private:  
        pthread_key_t pkey_;  
};  
/* 
 * 线程池 
 */  
class ThreadPool:noncopyable{  
    public:  
        typedef function<void()> Task;//线程工作函数  
        explicit ThreadPool(const string& name=string()):mutex_(),cond_(mutex_),name_(name),running_(false){  
        }  
        ~ThreadPool(){  
            if(running_){  
                stop();//等待所有线程池中的线程完成工作  
            }  
        }  
        void start(int numThreads){  
            assert(threads_.empty());  
            running_=true;  
            threads_.reserve(numThreads);  
            for(int i=0;i<numThreads;i++){  
                threads_.push_back(new Thread(bind(&ThreadPool::runInThread,this)));//池中线程运行runInThread工作函数  
                threads_[i].start();  
            }  
        }  
        void stop(){  
            running_=false;//可以提醒使用者不要在此后添加任务了，因为停止池但是池还要等待池中线程完成任务  
            cond_.notifyALL();//唤醒池中所有睡眠的线程  
            for_each(threads_.begin(),threads_.end(),bind(&Thread::join,_1));//等待池中线程完成  
        }  
        void run(const Task& task){  
            if(running_){//###4###防止停止池运行后还有任务加进来  
                if(threads_.empty()){//池中没有线程  
                    task();  
                }  
                else{  
                    MutexLockGuard guard(mutex_);//使用RAII mutex保证线程安全  
                    queue_.push_back(task);  
                    cond_.notify();  
                }  
            }  
            else{  
                printf("线程池已停止运行\n");  
            }  
        }  
        bool running(){//使用者可以获取线程池的运行状态  
            return running_;  
        }  
    private:  
        void runInThread(){//线程工作函数  
            while(running_){//###2###  
                Task task(take());  
                if(task){//task可能意外的为NULL  
                    task();  
                }  
            }  
        }  
        Task take(){  
            MutexLockGuard guard(mutex_);  
            while(queue_.empty()&&running_){//###3###和###2###不能保证在池停止运行但是线程还没有完成操作期间安全。假设此期间有任务添加到池中，且某个线程A执行到###2###后马上被切换了，池running_=false停止运行，A被切换后运行执行###3###处无意义啊，因为池已经停止运行了。所以###4###是有必要提醒使用者池停止这一情景  
                cond_.wait();//池中没有任务等待  
            }  
            Task task;  
            if(!queue_.empty()){  
                task=queue_.front();  
                queue_.pop_front();  
            }  
            return task;  
        }  
        Mutex mutex_;  
        Condition cond_;  
        string name_;  
        ptr_vector<Thread> threads_;//智能指针容器  
        deque<Task> queue_;  
        bool running_;  
};  
/* 
 * 原子类型 
 */  
template<typename T>  
class AtomicIntegerT : boost::noncopyable  
{  
    public:  
        AtomicIntegerT()  
            : value_(0){}  
        T get() const  
        {  
            return __sync_val_compare_and_swap(const_cast<volatile T*>(&value_), 0, 0);  
        }  
        T getAndAdd(T x)  
        {  
            return __sync_fetch_and_add(&value_, x);  
        }  
        T addAndGet(T x)  
        {  
            return getAndAdd(x) + x;  
        }  
        T incrementAndGet()  
        {  
            return addAndGet(1);  
        }  
        void add(T x)  
        {  
            getAndAdd(x);  
        }  
        void increment()  
        {  
            incrementAndGet();  
        }  
        void decrement()  
        {  
            getAndAdd(-1);  
        }  
        T getAndSet(T newValue)  
        {  
            return __sync_lock_test_and_set(&value_, newValue);  
        }  
    private:  
        volatile T value_;  
};  
typedef AtomicIntegerT<int32_t> AtomicInt32;  
typedef AtomicIntegerT<int64_t> AtomicInt64;  
  
class Channel;//前向声明，事件分发器主要用于事件注册与事件处理(事件回调)  
class Poller;//IO复用机制，主要功能是监听事件集合，即select，poll,epoll的功能  
class Timer;  
class TimerId;  
class Timestamp;  
class TimerQueue;  
class TcpConnection;  
class Buffer;  
  
typedef shared_ptr<TcpConnection> TcpConnectionPtr;  
typedef function<void()> TimerCallback;  
typedef function<void (const TcpConnectionPtr&)> ConnectionCallback;  
typedef function<void (const TcpConnectionPtr&,Buffer* buf)> MessageCallback;  
typedef function<void (const TcpConnectionPtr&)> WriteCompleteCallback;  
typedef function<void (const TcpConnectionPtr&)> CloseCallback;  
/* 
*EventLoop: 事件循环，一个线程一个事件循环即one loop per thread，其主要功能是运行事件循环如等待事件发生然后处理发生的事件 
*/  
class EventLoop:noncopyable{  
    public:  
        //实现事件循环  
        //实现定时回调功能，通过timerfd和TimerQueue实现  
        //实现用户任务回调，为了线程安全有可能其它线程向IO线程的EventLoop添加任务，此时通过eventfd通知EventLoop执行用户任务  
        typedef function<void()> Functor;//回调函数  
        EventLoop();  
        ~EventLoop();  
        void loop();//EventLoop的主体,用于事件循环，Eventloop::loop()->Poller::Poll()获得就绪的事件集合并通过Channel::handleEvent()执行就绪事件回调  
        void quit();//终止事件循环，通过设定标志位所以有一定延迟  
        //Timestamp pollReturnTime() const;  
        void assertInLoopThread(){//若运行线程不拥有EventLoop则退出，保证one loop per thread  
            if(!isInLoopThread()){  
                abortNotInLoopThread();  
            }  
        }  
        bool isInLoopThread() const{return threadID_==syscall(SYS_gettid);}//判断运行线程是否为拥有此EventLoop的线程  
        TimerId runAt(const Timestamp& time,const TimerCallback& cb);//绝对时间执行定时器回调cb  
        TimerId runAfter(double delay,const TimerCallback& cb);//相对时间执行定时器回调  
        TimerId runEvery(double interval,const TimerCallback& cb);//每隔interval执行定时器回调  
        void runInLoop(const Functor& cb);//用于IO线程执行用户回调(如EventLoop由于执行事件回调阻塞了，此时用户希望唤醒EventLoop执行用户指定的任务)  
        void queueInLoop(const Functor& cb);//唤醒IO线程(拥有此EventLoop的线程)并将用户指定的任务回调放入队列  
        void cancel(TimerId tiemrId);  
        void wakeup();//唤醒IO线程  
        void updateChannel(Channel* channel);//更新事件分发器Channel，完成文件描述符fd向事件集合注册事件及事件回调函数  
        void removeChannel(Channel* channel);  
    private:  
        void abortNotInLoopThread();//在不拥有EventLoop线程中终止  
        void handleRead();//timerfd上可读事件回调  
        void doPendingFunctors();//执行队列pendingFunctors中的用户任务回调  
        typedef vector<Channel*> ChannelList;//事件分发器Channel容器，一个Channel只负责一个文件描述符fd的事件分发  
        bool looping_;//事件循环主体loop是运行标志  
        bool quit_;//取消循环主体标志  
        const pid_t threadID_;//EventLoop的附属线程ID  
        scoped_ptr<Poller> poller_;//IO复用器Poller用于监听事件集合  
        //scoped_ptr<Epoller> poller_;  
        ChannelList activeChannels_;//类似与poll的就绪事件集合，这里集合换成Channel(事件分发器具备就绪事件回调功能)  
        //Timestamp pollReturnTime_;  
        int wakeupFd_;//eventfd用于唤醒EventLoop所在线程  
        scoped_ptr<Channel> wakeupChannel_;//通过wakeupChannel_观察wakeupFd_上的可读事件，当可读时表明需要唤醒EventLoop所在线程执行用户回调  
        Mutex mutex_;//互斥量用以保护队列  
        vector<Functor> pendingFunctors_;//用户任务回调队列  
        scoped_ptr<TimerQueue> timerQueue_;//定时器队列用于存放定时器  
        bool callingPendingFunctors_;//是否有用户任务回调标志  
};  
  
/* 
 *Poller: IO Multiplexing Poller即poll的封装，主要完成事件集合的监听 
 */  
class Poller:noncopyable{//生命期和EventLoop一样长，不拥有Channel  
    public:  
        typedef vector<Channel*> ChannelList;//Channel容器(Channel包含了文件描述符fd和fd注册的事件及事件回调函数)，Channel包含文件描述符及其注册事件及其事件回调函数，这里主要用于返回就绪事件集合  
        Poller(EventLoop* loop);  
        ~Poller();  
        Timestamp Poll(int timeoutMs,ChannelList* activeChannels);//Poller的核心功能，通过poll系统调用将就绪事件集合通过activeChannels返回，并EventLoop::loop()->Channel::handelEvent()执行相应的就绪事件回调  
        void updateChannel(Channel* channel);//Channel::update(this)->EventLoop::updateChannel(Channel*)->Poller::updateChannel(Channel*)负责维护和更新pollfs_和channels_,更新或添加Channel到Poller的pollfds_和channels_中(主要是文件描述符fd对应的Channel可能想修改已经向poll注册的事件或者fd想向poll注册事件)  
        void assertInLoopThread(){//判定是否和EventLoop的隶属关系，EventLoop要拥有此Poller  
            ownerLoop_->assertInLoopThread();  
        }  
        void removeChannel(Channel* channel);//通过EventLoop::removeChannel(Channel*)->Poller::removeChannle(Channel*)注销pollfds_和channels_中的Channel  
    private:  
        void fillActiveChannels(int numEvents,ChannelList* activeChannels) const;//遍历pollfds_找出就绪事件的fd填入activeChannls,这里不能一边遍历pollfds_一边执行Channel::handleEvent()因为后者可能添加或者删除Poller中含Channel的pollfds_和channels_(遍历容器的同时存在容器可能被修改是危险的),所以Poller仅仅是负责IO复用，不负责事件分发(交给Channel处理)  
        typedef vector<struct pollfd> PollFdList;//struct pollfd是poll系统调用监听的事件集合参数  
        typedef map<int,Channel*> ChannelMap;//文件描述符fd到IO分发器Channel的映射，通过fd可以快速找到Channel  
        //注意:Channel中有fd成员可以完成Channel映射到fd的功能，所以fd和Channel可以完成双射  
        EventLoop* ownerLoop_;//隶属的EventLoop  
        PollFdList pollfds_;//监听事件集合  
        ChannelMap channels_;//文件描述符fd到Channel的映射  
};  
  
/* 
 *Channel: 事件分发器,该类包含：文件描述符fd、fd欲监听的事件、事件的处理函数(事件回调函数) 
 */  
class Channel:noncopyable{  
    public:  
        typedef function<void()> EventCallback;//事件回调函数类型,回调函数的参数为空，这里将参数类型已经写死了  
        typedef function<void()> ReadEventCallback;  
        Channel(EventLoop* loop,int fd);//一个Channel只负责一个文件描述符fd但Channel不拥有fd，可见结构应该是这样的：EventLoop调用Poller监听事件集合，就绪的事件集合元素就是Channel。但Channel的功能不仅是返回就绪事件，还具备事件处理功能  
        ~Channel();//目前缺失一个功能：~Channel()->EventLoop::removeChannel()->Poller::removeChannel()注销Poller::map<int,Channel*>的Channel*避免空悬指针  
        void handleEvent();//这是Channel的核心，当fd对应的事件就绪后Channel::handleEvent()执行相应的事件回调，如可读事件执行readCallback_()  
        void setReadCallback(const ReadEventCallback& cb){//可读事件回调  
            readCallback_=cb;  
        }  
        void setWriteCallback(const EventCallback& cb){//可写事件回调  
            writeCallback_=cb;  
        }  
        void setErrorCallback(const EventCallback& cb){//出错事件回调  
            errorCallback_=cb;  
        }  
        void setCloseCallback(const EventCallback& cb){  
            closeCallback_=cb;  
        }  
        int fd() const{return fd_;}//返回Channel负责的文件描述符fd，即建立Channel到fd的映射  
        int events() const{return events_;}//返回fd域注册的事件类型  
        void set_revents(int revt){//设定fd的就绪事件类型，再poll返回就绪事件后将就绪事件类型传给此函数，然后此函数传给handleEvent，handleEvent根据就绪事件的类型决定执行哪个事件回调函数  
            revents_=revt;  
        }  
        bool isNoneEvent() const{//fd没有想要注册的事件  
            return events_==kNoneEvent;  
        }  
        void enableReading(){//fd注册可读事件  
            events_|=kReadEvent;  
            update();  
        }  
        void enableWriting(){//fd注册可写事件  
            events_|=kWriteEvent;  
            update();  
        }  
        void disableWriting(){  
            events_&=~kWriteEvent;  
            update();  
        }  
        void disableAll(){events_=kReadEvent;update();}  
        bool isWriting() const{  
            return events_&kWriteEvent;  
        }  
        int index(){return index_;}//index_是本Channel负责的fd在poll监听事件集合的下标，用于快速索引到fd的pollfd  
        void set_index(int idx){index_=idx;}  
        EventLoop* ownerLoop(){return loop_;}  
    private:  
        void update();//Channel::update(this)->EventLoop::updateChannel(Channel*)->Poller::updateChannel(Channel*)最后Poller修改Channel，若Channel已经存在于Poller的vector<pollfd> pollfds_(其中Channel::index_是vector的下标)则表明Channel要重新注册事件，Poller调用Channel::events()获得事件并重置vector中的pollfd;若Channel没有在vector中则向Poller的vector添加新的文件描述符事件到事件表中，并将vector.size(),(vector每次最后追加)，给Channel::set_index()作为Channel记住自己在Poller中的位置  
        static const int kNoneEvent;//无任何事件  
        static const int kReadEvent;//可读事件  
        static const int kWriteEvent;//可写事件  
        bool eventHandling_;  
        EventLoop* loop_;//Channel隶属的EventLoop(原则上EventLoop，Poller，Channel都是一个IO线程)  
        const int fd_;//每个Channel唯一负责的文件描述符，Channel不拥有fd  
        int events_;//fd_注册的事件  
        int revents_;//通过poll返回的就绪事件类型  
        int index_;//在poll的监听事件集合pollfd的下标，用于快速索引到fd的pollfd  
        ReadEventCallback readCallback_;//可读事件回调函数，当poll返回fd_的可读事件时调用此函数执行相应的事件处理，该函数由用户指定  
        EventCallback writeCallback_;//可写事件回调函数  
        EventCallback errorCallback_;//出错事件回调函数  
        EventCallback closeCallback_;  
};  
  
/* 
*时间戳，采用一个整数表示微秒数 
*/  
class Timestamp{  
    public:  
        Timestamp():microSecondsSinceEpoch_(0){}  
        explicit Timestamp(int64_t microseconds):microSecondsSinceEpoch_(microseconds){}  
        void swap(Timestamp& that){  
            std::swap(microSecondsSinceEpoch_,that.microSecondsSinceEpoch_);  
        }  
        bool valid() const{return microSecondsSinceEpoch_>0;}  
        int64_t microSecondsSinceEpoch() const {return microSecondsSinceEpoch_;}  
        static Timestamp now(){  
            struct timeval tv;  
            gettimeofday(&tv, NULL);  
            int64_t seconds = tv.tv_sec;  
            return Timestamp(seconds * kMicroSecondsPerSecond + tv.tv_usec);  
        }  
        static Timestamp invalid(){return Timestamp();}  
        static const int kMicroSecondsPerSecond=1000*1000;  
    private:  
        int64_t microSecondsSinceEpoch_;  
};  
//时间戳的比较  
inline bool operator<(Timestamp lhs, Timestamp rhs)  
{  
  return lhs.microSecondsSinceEpoch() < rhs.microSecondsSinceEpoch();  
}  
  
inline bool operator==(Timestamp lhs, Timestamp rhs)  
{  
  return lhs.microSecondsSinceEpoch() == rhs.microSecondsSinceEpoch();  
}  
inline double timeDifference(Timestamp high, Timestamp low)  
{  
  int64_t diff = high.microSecondsSinceEpoch() - low.microSecondsSinceEpoch();  
  return static_cast<double>(diff) / Timestamp::kMicroSecondsPerSecond;  
}  
inline Timestamp addTime(Timestamp timestamp, double seconds)  
{  
  int64_t delta = static_cast<int64_t>(seconds * Timestamp::kMicroSecondsPerSecond);  
  return Timestamp(timestamp.microSecondsSinceEpoch() + delta);  
}  
/* 
 * TimerId带有唯一序号的Timer 
 */  
class TimerId{  
    public:  
        TimerId(Timer* timer=NULL,int64_t seq=0)  
            :timer_(timer),sequence_(seq){}  
        friend class TimerQueue;  
    private:  
        Timer* timer_;  
        int64_t sequence_;  
};  
/* 
 *定时器 
 */  
class Timer : boost::noncopyable  
{  
    public:  
        typedef function<void()> TimerCallback;//定时器回调函数  
        //typedef function<void()> callback;  
        Timer(const TimerCallback& cb, Timestamp when, double interval)  
            :callback_(cb),expiration_(when),  
            interval_(interval),repeat_(interval > 0.0),  
            sequence_(s_numCreated_.incrementAndGet()){}  
        void run() const {//执行定时器回调  
            callback_();  
        }  
        Timestamp expiration() const  { return expiration_; }//返回定时器的超时时间戳  
        bool repeat() const { return repeat_; }//是否周期性定时  
        int64_t sequence() const{return sequence_;}  
        void restart(Timestamp now);//重置定时器  
     private:  
        const TimerCallback callback_;//超时回调函数  
        Timestamp expiration_;//超时时间戳  
        const double interval_;//相对时间，作为参数传给时间戳生成具体的超时时间  
        const bool repeat_;//是否重复定时标志  
        const int64_t sequence_;//  
        static AtomicInt64 s_numCreated_;//原子操作，用于生成定时器ID  
};  
AtomicInt64 Timer::s_numCreated_;  
void Timer::restart(Timestamp now){  
    if (repeat_){//周期定时  
        expiration_ = addTime(now, interval_);  
    }  
    else{  
        expiration_ = Timestamp::invalid();  
    }  
}  
/* 
 * timerfd的相关操作,可用于TimerQueue实现超时器管理 
 */  
int createTimerfd(){//创建timerfd  
    int timerfd = ::timerfd_create(CLOCK_MONOTONIC,TFD_NONBLOCK | TFD_CLOEXEC);  
    if (timerfd < 0){  
        printf("Timderfd::create() error\n");  
    }  
    return timerfd;  
}  
struct timespec howMuchTimeFromNow(Timestamp when){  
    int64_t microseconds = when.microSecondsSinceEpoch()- Timestamp::now().microSecondsSinceEpoch();  
    if (microseconds < 100){  
        microseconds = 100;  
    }  
    struct timespec ts;  
    ts.tv_sec = static_cast<time_t>(microseconds / Timestamp::kMicroSecondsPerSecond);  
    ts.tv_nsec = static_cast<long>((microseconds % Timestamp::kMicroSecondsPerSecond) * 1000);  
    return ts;  
}  
void readTimerfd(int timerfd, Timestamp now){//timerfd的可读事件回调  
    uint64_t howmany;  
    ssize_t n = ::read(timerfd, &howmany, sizeof howmany);  
    if (n != sizeof howmany){  
        printf("readTimerfd error\n");  
    }  
}  
void resetTimerfd(int timerfd, Timestamp expiration)//重置timerfd的计时  
{  
    struct itimerspec newValue;  
    struct itimerspec oldValue;  
    bzero(&newValue, sizeof newValue);  
    bzero(&oldValue, sizeof oldValue);  
    newValue.it_value = howMuchTimeFromNow(expiration);  
    int ret = ::timerfd_settime(timerfd, 0, &newValue, &oldValue);  
    if (ret){  
        printf("timerfd_settime erro\n");  
    }  
}  
/* 
 *定时器队列 
 */  
class TimerQueue : boost::noncopyable  
{//其通过添加一个timerfd到EventLoop中，当timerfd可读事件就绪时，TimerQueue::handleRead()遍历容器内的超时的定时器并执行这些超时定时器的回调  
 //定时器容器为set<pair<Timestamp,Timer*> >，采用pair作为key的原因是可能在一个时刻有多个相同的Timestamp时间戳  
 //当向定时器容器set添加定时器timer的时候会检查当前最小的定时器，并将最小的定时时间付赋给timerfd  
    public:  
        typedef function<void()> TimerCallback;//定时器回调  
        TimerQueue(EventLoop* loop);  
        ~TimerQueue();  
        TimerId addTimer(const TimerCallback& cb,Timestamp when,double interval);//添加定时器到定时器队列中  
        void cancel(TimerId timerId);  
    private:  
        typedef pair<Timestamp, Timer*> Entry;//采用此作为键值  
        typedef set<Entry> TimerList;//set只有key无value且有序  
        typedef pair<Timer*,int64_t> ActiveTimer;  
        typedef set<ActiveTimer> ActiveTimerSet;  
  
        void handleRead();//timerfd的可读回调  
        void addTimerInLoop(Timer* timer);//添加定时器  
        void cancelInLoop(TimerId timerId);  
        std::vector<Entry> getExpired(Timestamp now);//获取所有超时的定时器  
        void reset(const std::vector<Entry>& expired, Timestamp now);//超时的定时器是否需要重新定时  
        bool insert(Timer* timer);//插入定时器到队列中  
  
        EventLoop* loop_;//TimerQueue所属的EventLoop  
        const int timerfd_;//定时器队列本身需要在定时器超时后执行队列中所有超时定时器的回调  
        Channel timerfdChannel_;//采用timerfdChannel_观察timerfd_的可读事件啊，当timerfd_可读表明定时器队列中有定时器超时  
        TimerList timers_;//定时器队列  
        bool callingExpiredTimers_;  
        ActiveTimerSet activeTimers_;  
        ActiveTimerSet cancelingTimers_;  
};  
/* 
 * TimerQueue实现 
 */  
TimerQueue::TimerQueue(EventLoop* loop)  
    :loop_(loop),timerfd_(createTimerfd()),  
    timerfdChannel_(loop, timerfd_),timers_(),  
    callingExpiredTimers_(false)  
{  
    timerfdChannel_.setReadCallback(bind(&TimerQueue::handleRead, this));  
    timerfdChannel_.enableReading();//timerfd注册可读事件  
}  
TimerQueue::~TimerQueue(){  
    ::close(timerfd_);  
    for (TimerList::iterator it = timers_.begin();it != timers_.end(); ++it)  
    {  
        delete it->second;  
    }  
}  
TimerId TimerQueue::addTimer(const TimerCallback& cb,Timestamp when,double interval)//其它线程向IO线程添加用户回调时将添加操作转移到IO线程中去，从而保证线程安全one loop per thread  
{//由EventLoop::runAt等函数调用  
    Timer* timer = new Timer(cb, when, interval);  
    loop_->runInLoop(bind(&TimerQueue::addTimerInLoop,this,timer));//通过EventLoop::runInLoop()->TimerQueue::queueInLoop()  
    //runInLoop语义是若是本IO线程想要添加定时器则直接由addTimerInLoop添加，若是其它线程向IO线程添加定时器则需要间接通过queueInLoop添加  
    return TimerId(timer,timer->sequence());  
}  
void TimerQueue::addTimerInLoop(Timer* timer){//IO线程自己向自己添加定时器  
    loop_->assertInLoopThread();  
    bool earliestChanged=insert(timer);//若当前插入的定时器比队列中的定时器都早则返回真  
    if(earliestChanged){  
        resetTimerfd(timerfd_,timer->expiration());//timerfd重新设置超时时间  
    }  
}  
void TimerQueue::cancel(TimerId timerId){  
    loop_->runInLoop(bind(&TimerQueue::cancelInLoop,this,timerId));  
}  
void TimerQueue::cancelInLoop(TimerId timerId){  
    loop_->assertInLoopThread();  
    assert(timers_.size()==activeTimers_.size());  
    ActiveTimer timer(timerId.timer_,timerId.sequence_);  
    ActiveTimerSet::iterator it=activeTimers_.find(timer);  
    if(it!=activeTimers_.end()){  
        size_t n=timers_.erase(Entry(it->first->expiration(),it->first));  
        assert(n==1);  
        (void)n;  
        delete it->first;  
        activeTimers_.erase(it);  
    }  
    else if(callingExpiredTimers_){  
        cancelingTimers_.insert(timer);  
    }  
    assert(timers_.size()==activeTimers_.size());  
}  
void TimerQueue::handleRead(){//timerfd的回调函数  
    loop_->assertInLoopThread();  
    Timestamp now(Timestamp::now());  
    readTimerfd(timerfd_, now);  
    std::vector<Entry> expired = getExpired(now);//TimerQueue::timerfd可读表明队列中有定时器超时，则需要找出那些超时的定时器  
    callingExpiredTimers_=true;  
    cancelingTimers_.clear();  
    for (std::vector<Entry>::iterator it = expired.begin();it!= expired.end(); ++it)//  
    {  
        it->second->run();//执行定时器Timer的超时回调  
    }  
    callingExpiredTimers_=false;  
    reset(expired, now);//查看已经执行完的超市定时器是否需要再次定时  
}  
std::vector<TimerQueue::Entry> TimerQueue::getExpired(Timestamp now)//获取队列中的超时的定时器(可能多个)  
{  
    assert(timers_.size()==activeTimers_.size());  
    std::vector<Entry> expired;  
    Entry sentry = std::make_pair(now, reinterpret_cast<Timer*>(UINTPTR_MAX));  
    TimerList::iterator it = timers_.lower_bound(sentry);//返回比参数小的下界，即返回第一个当前未超时的定时器(可能没有这样的定时器)  
    //lower_bound(value_type& val)调用key_comp返回第一个不小于val的迭代器  
    assert(it == timers_.end() || now < it->first);  
    std::copy(timers_.begin(), it, back_inserter(expired));  
    timers_.erase(timers_.begin(), it);  
    BOOST_FOREACH(Entry entry,expired){  
        ActiveTimer timer(entry.second,entry.second->sequence());  
        size_t n=activeTimers_.erase(timer);  
        assert(n==1);  
        (void)n;  
    }  
    return expired;//返回已经超时的那部分定时器  
}  
  
void TimerQueue::reset(const std::vector<Entry>& expired, Timestamp now)//已经执行完超时回调的定时器是否需要重置定时  
{  
    Timestamp nextExpire;  
    for (std::vector<Entry>::const_iterator it = expired.begin();it != expired.end(); ++it)  
    {  
        ActiveTimer timer(it->second,it->second->sequence());  
        if (it->second->repeat()&&  
                cancelingTimers_.find(timer)==cancelingTimers_.end()){//需要再次定时  
            it->second->restart(now);  
            insert(it->second);  
        }  
        else{//否则删除该定时器  
            delete it->second;  
        }  
    }  
    if (!timers_.empty()){//为超时定时器重新定时后需要获取当前最小的超时时间给timerfd，以防重置的这些超市定时器中含有最小的超时时间  
        nextExpire = timers_.begin()->second->expiration();  
    }  
    if (nextExpire.valid()){  
        resetTimerfd(timerfd_, nextExpire);//重置timerfd的超时时间  
    }  
}  
bool TimerQueue::insert(Timer* timer)//向超时队列中插入定时器  
{  
    loop_->assertInLoopThread();  
    assert(timers_.size()==activeTimers_.size());  
    bool earliestChanged = false;  
    Timestamp when = timer->expiration();  
    TimerList::iterator it = timers_.begin();  
    if (it == timers_.end() || when < it->first)  
    {  
        earliestChanged = true;//当前插入的定时器是队列中最小的定时器，此时外层函数需要重置timerfd的超时时间  
    }  
    {  
        pair<TimerList::iterator,bool> result=  
            timers_.insert(Entry(when,timer));  
        assert(result.second);  
        (void)result;  
    }  
    {  
        pair<ActiveTimerSet::iterator,bool> result=  
            activeTimers_.insert(ActiveTimer(timer,timer->sequence()));  
        assert(result.second);  
        (void)result;  
    }  
    assert(timers_.size()==activeTimers_.size());  
    return earliestChanged;  
}  
  
/* 
*EventLoop成员实现 
*/  
class IngnoreSigPipe{  
    public:  
        IngnoreSigPipe(){  
            ::signal(SIGPIPE,SIG_IGN);  
        }  
};  
IngnoreSigPipe initObj;  
__thread EventLoop* t_loopInThisThread=0;//线程私有数据表示线程是否拥有EventLoop  
const int kPollTimeMs=10000;//poll等待时间  
static int createEventfd(){//创建eventfd，eventfd用于唤醒  
    int evtfd=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);  
    if(evtfd<0){  
        printf("Failed in eventfd\n");  
        abort();  
    }  
    return evtfd;  
}  
EventLoop::EventLoop()  
    :looping_(false),  
    quit_(false),  
    threadID_(syscall(SYS_gettid)),  
    poller_(new Poller(this)),  
    timerQueue_(new TimerQueue(this)),//EventLoop用于一个定时器队列  
    wakeupFd_(createEventfd()),  
    wakeupChannel_(new Channel(this,wakeupFd_)),//通过Channel观察wakeupFd_  
    callingPendingFunctors_(false)  
{  
    if(!t_loopInThisThread){  
        t_loopInThisThread=this;//EventLoop构造时线程私有数据记录  
    }  
    wakeupChannel_->setReadCallback(bind(&EventLoop::handleRead,this));//设置eventfd的回调  
    wakeupChannel_->enableReading();//eventfd的可读事件,并Channel::update(this)将eventfd添加到poll事件表中  
}  
EventLoop::~EventLoop(){  
    assert(!looping_);  
    close(wakeupFd_);  
    t_loopInThisThread=NULL;//EventLoop析构将其置空  
}  
void EventLoop::loop(){//EventLoop主循环，主要功能是监听事件集合，执行就绪事件的处理函数  
    assert(!looping_);  
    assertInLoopThread();  
    looping_=true;  
    quit_=false;  
    while(!quit_){  
        activeChannels_.clear();  
        poller_->Poll(kPollTimeMs,&activeChannels_);//activeChannels是就绪事件  
        for(ChannelList::iterator it=activeChannels_.begin();it!=activeChannels_.end();it++){  
            (*it)->handleEvent();//处理就绪事件的回调函数，处理事件回调  
        }  
        doPendingFunctors();//处理用户任务回调  
    }  
    looping_=false;  
}  
void EventLoop::quit(){  
    quit_=true;//停止主循环标志，主循环不会马上停止有延迟  
    if(!isInLoopThread()){  
        wakeup();//其它线程唤醒EventLoop线程且终止它  
    }  
}  
void EventLoop::updateChannel(Channel* channel){//主要用于文件描述符添加到poll的监听事件集合中  
    assert(channel->ownerLoop()==this);  
    assertInLoopThread();  
    poller_->updateChannel(channel);  
}  
void EventLoop::abortNotInLoopThread(){  
    printf("abort not in Loop Thread\n");  
    abort();//非本线程调用强行终止  
}  
TimerId EventLoop::runAt(const Timestamp& time, const TimerCallback& cb)//绝对时间执行回调  
{  
    return timerQueue_->addTimer(cb, time, 0.0);  
}  
TimerId EventLoop::runAfter(double delay, const TimerCallback& cb)//相对时间执行回调  
{  
    Timestamp time(addTime(Timestamp::now(), delay));  
    return runAt(time, cb);  
}  
TimerId EventLoop::runEvery(double interval, const TimerCallback& cb)//周期性回调  
{  
    Timestamp time(addTime(Timestamp::now(), interval));//Timestamp::addTime  
    return timerQueue_->addTimer(cb, time, interval);  
}  
void EventLoop::cancel(TimerId timerId){  
    return timerQueue_->cancel(timerId);  
}  
void EventLoop::runInLoop(const Functor& cb){  
    if(isInLoopThread()){//本IO线程调用则直接执行执行用户回调  
       cb();  
    }  
    else{//其它线程调用runInLoop则向用户回调队列添加，保证线程安全one loop per thread  
        queueInLoop(cb);  
    }  
}  
void EventLoop::queueInLoop(const Functor& cb){  
    {  
        MutexLockGuard lock(mutex_);//互斥量保护用户回调队列  
        pendingFunctors_.push_back(cb);  
    }  
    if(!isInLoopThread()||callingPendingFunctors_){  
        wakeup();//其它线程添加用户回调任务或者EventLoop的IO线程正在处理用户任务回调时，若阻塞则唤醒IO线程  
    }  
}  
void EventLoop::handleRead(){//eventfd可读回调  
    uint64_t one=1;  
    ssize_t n=read(wakeupFd_,&one,sizeof(one));  
    if(n!=sizeof(one)){  
        printf("EventLoop::handleRead() error\n");  
    }  
}  
void EventLoop::doPendingFunctors(){//执行用户任务回调  
    vector<Functor> functors;  
    callingPendingFunctors_=true;  
    {  
        MutexLockGuard lock(mutex_);  
        functors.swap(pendingFunctors_);//采用swap而不是在这里执行回调是为了缩小临界区  
    }  
    for(size_t i=0;i<functors.size();i++){  
        functors[i]();  
    }  
    callingPendingFunctors_=false;  
}  
void EventLoop::wakeup(){  
    uint64_t one=1;  
    ssize_t n=write(wakeupFd_,&one,sizeof(one));//通过eventfd通知  
    if(n!=sizeof(one)){  
        printf("EventLoop::wakeup() write error\n");  
    }  
}  
void EventLoop::removeChannel(Channel* channel){  
    assert(channel->ownerLoop()==this);  
    assertInLoopThread();  
    poller_->removeChannel(channel);  
}  
  
/* 
*Poller成员实现 
*/  
Poller::Poller(EventLoop* loop):ownerLoop_(loop){}//Poller明确所属的EventLoop  
Poller::~Poller(){}  
Timestamp Poller::Poll(int timeoutMs,ChannelList* activeChannels){  
    int numEvents=poll(&*pollfds_.begin(),pollfds_.size(),timeoutMs);//poll监听事件集合pollfds_  
    Timestamp now(Timestamp::now());  
    if(numEvents>0){  
        fillActiveChannels(numEvents,activeChannels);//将就绪的事件添加到activeChannels  
    }  
    else if(numEvents==0){  
    }  
    else{  
        printf("Poller::Poll error\n");  
    }  
    return now;  
}  
void Poller::fillActiveChannels(int numEvents,ChannelList* activeChannels) const{//将就绪事件通过activeChannels返回  
    for(PollFdList::const_iterator pfd=pollfds_.begin();pfd!=pollfds_.end()&&numEvents>0;++pfd){  
        if(pfd->revents>0){  
            --numEvents;//若numEvents个事件全部找到就不需要再遍历容器剩下的部分  
            ChannelMap::const_iterator ch=channels_.find(pfd->fd);  
            assert(ch!=channels_.end());  
            Channel* channel=ch->second;  
            assert(channel->fd()==pfd->fd);  
            channel->set_revents(pfd->revents);  
            activeChannels->push_back(channel);  
        }  
    }  
}  
void Poller::updateChannel(Channel* channel){  
    assertInLoopThread();  
    if(channel->index()<0){//若channel的文件描述符fd没有添加到poll的监听事件集合中  
        assert(channels_.find(channel->fd())==channels_.end());  
        struct pollfd pfd;  
        pfd.fd=channel->fd();  
        pfd.events=static_cast<short>(channel->events());  
        pfd.revents=0;  
        pollfds_.push_back(pfd);  
        int idx=static_cast<int>(pollfds_.size())-1;  
        channel->set_index(idx);  
        channels_[pfd.fd]=channel;  
    }  
    else{//若已经添加到监听事件集合中，但是需要修改  
        assert(channels_.find(channel->fd())!=channels_.end());  
        assert(channels_[channel->fd()]==channel);  
        int idx=channel->index();  
        assert(0<=idx&&idx<static_cast<int>(pollfds_.size()));  
        struct pollfd& pfd=pollfds_[idx];  
        assert(pfd.fd==channel->fd()||pfd.fd==-channel->fd()-1);//pfd.fd=-channel->fd()-1是为了让poll忽略那些kNoneEvent的描述符，-1是因为:fd可能为0所以-channel->fd()可能还是0,不能区分一个不可能的描述符  
        pfd.events=static_cast<short>(channel->events());//修改注册事件类型  
        pfd.revents=0;  
        if(channel->isNoneEvent()){  
            pfd.fd=-channel->fd()-1;//channel::events_=kNoneEvent时poll忽略那些不可能的描述符-channel->fd()-1,-1原因见上面  
        }  
    }  
}  
void Poller::removeChannel(Channel* channel)  
{  
  assertInLoopThread();  
  assert(channels_.find(channel->fd()) != channels_.end());  
  assert(channels_[channel->fd()] == channel);  
  assert(channel->isNoneEvent());  
  int idx = channel->index();  
  assert(0 <= idx && idx < static_cast<int>(pollfds_.size()));  
  const struct pollfd& pfd = pollfds_[idx]; (void)pfd;  
  assert(pfd.fd == -channel->fd()-1 && pfd.events == channel->events());  
  size_t n = channels_.erase(channel->fd());  
  assert(n == 1); (void)n;  
  if (implicit_cast<size_t>(idx) == pollfds_.size()-1) {  
    pollfds_.pop_back();  
  } else {  
    int channelAtEnd = pollfds_.back().fd;  
    iter_swap(pollfds_.begin()+idx, pollfds_.end()-1);  
    if (channelAtEnd < 0) {  
      channelAtEnd = -channelAtEnd-1;  
    }  
    channels_[channelAtEnd]->set_index(idx);  
    pollfds_.pop_back();  
  }  
}  
/* 
*Channel成员实现 
*/  
const int Channel::kNoneEvent=0;//无事件  
const int Channel::kReadEvent=POLLIN|POLLPRI;//可读事件  
const int Channel::kWriteEvent=POLLOUT;//可写事件  
Channel::Channel(EventLoop* loop,int fdArg)  
    :loop_(loop),fd_(fdArg),events_(0),revents_(0),  
    index_(-1),eventHandling_(false)  
    {}  
void Channel::update(){//添加或修改文件描述符的事件类型  
    loop_->updateChannel(this);  
}  
Channel::~Channel(){  
    assert(!eventHandling_);  
}  
void Channel::handleEvent(){//处理就绪事件的处理函数  
    eventHandling_=true;  
    if(revents_&POLLNVAL){  
        printf("Channel::handleEvent() POLLNVAL\n");  
    }  
    if((revents_&POLLHUP)&&!(revents_&POLLIN)){//出错回调  
        printf("Channel::handle_event() POLLUP\n");  
        if(closeCallback_)  
            closeCallback_();  
    }  
    if(revents_&(POLLERR|POLLNVAL)){//可读回调  
        if(errorCallback_)  
            errorCallback_();  
    }  
    if(revents_&(POLLIN|POLLPRI|POLLRDHUP)){  
        if(readCallback_) readCallback_();  
    }  
    if(revents_&POLLOUT){//可写回调  
        if(writeCallback_)  
            writeCallback_();  
    }  
    eventHandling_=false;  
}  
  
/* 
*开启一个线程执行一个EventLoop，这才是one loop per thread 
*/  
class EventLoopThread:noncopyable{  
    public:  
        EventLoopThread()  
            :loop_(NULL),exiting_(false),  
            thread_(bind(&EventLoopThread::threadFunc,this)),  
            mutex_(),cond_(mutex_){}  
        ~EventLoopThread(){  
            exiting_=true;  
            loop_->quit();  
            thread_.join();  
        }  
        EventLoop* startLoop(){  
            //assert(!thread_.started());  
            thread_.start();  
            {  
                MutexLockGuard lock(mutex_);  
                while(loop_==NULL){  
                    cond_.wait();  
                }  
            }  
            return loop_;  
        }  
    private:  
        void threadFunc(){  
            EventLoop loop;  
            {  
                MutexLockGuard lock(mutex_);  
                loop_=&loop;  
                cond_.notify();  
            }  
            loop.loop();  
        }  
        EventLoop* loop_;  
        bool exiting_;  
        Thread thread_;  
        Mutex mutex_;  
        Condition cond_;  
};  
/* 
 * EventLoopThreadPool 
 */  
class EventLoopThreadPool:noncopyable{  
    public:  
        EventLoopThreadPool(EventLoop* baseLoop)  
            :baseLoop_(baseLoop),  
            started_(false),numThreads_(0),next_(0){}  
        ~EventLoopThreadPool(){}  
        void setThreadNum(int numThreads){numThreads_=numThreads;}  
        void start(){  
            assert(!started_);  
            baseLoop_->assertInLoopThread();  
            started_=true;  
            for(int i=0;i<numThreads_;i++){  
                EventLoopThread* t=new EventLoopThread;  
                threads_.push_back(t);  
                loops_.push_back(t->startLoop());  
            }  
        }  
        EventLoop* getNextLoop(){  
            baseLoop_->assertInLoopThread();  
            EventLoop* loop=baseLoop_;  
            if(!loops_.empty()){  
                loop=loops_[next_];  
                ++next_;  
                if(static_cast<size_t>(next_)>=loops_.size())  
                    next_=0;  
            }  
            return loop;  
        }  
    private:  
        EventLoop* baseLoop_;  
        bool started_;  
        int numThreads_;  
        int next_;  
        ptr_vector<EventLoopThread> threads_;  
        vector<EventLoop*> loops_;  
};  
/* 
 *常用的socket选项 
 */  
namespace sockets{  
  
inline uint64_t hostToNetwork64(uint64_t host64)  
{//主机字节序转为网络字节序  
     return htobe64(host64);  
}  
inline uint32_t hostToNetwork32(uint32_t host32)  
{  
    return htonl(host32);  
}  
inline uint16_t hostToNetwork16(uint16_t host16)  
{  
    return htons(host16);  
}  
inline uint64_t networkToHost64(uint64_t net64)  
{//网络字节序转为主机字节序  
    return be64toh(net64);  
}  
  
inline uint32_t networkToHost32(uint32_t net32)  
{  
    return ntohl(net32);  
}  
inline uint16_t networkToHost16(uint16_t net16)  
{  
    return ntohs(net16);  
}  
  
typedef struct sockaddr SA;  
const SA* sockaddr_cast(const struct sockaddr_in* addr){//强制转换  
    return static_cast<const SA*>(implicit_cast<const void*>(addr));  
}  
SA* sockaddr_cast(struct sockaddr_in* addr){  
    return static_cast<SA*>(implicit_cast<void*>(addr));  
}  
void setNonBlockAndCloseOnExec(int sockfd){//将描述符设置为非阻塞和O_CLOEXEC(close on exec)  
    int flags = ::fcntl(sockfd, F_GETFL, 0);  
    flags |= O_NONBLOCK;  
    int ret = ::fcntl(sockfd, F_SETFL, flags);  
    flags = ::fcntl(sockfd, F_GETFD, 0);  
    flags |= FD_CLOEXEC;  
    ret = ::fcntl(sockfd, F_SETFD, flags);  
}  
int createNonblockingOrDie()  
{//socket()创建非阻塞的socket描述符  
    #if VALGRIND  
    int sockfd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);  
    if (sockfd < 0) {  
        printf("socket() error\n");  
    }  
    setNonBlockAndCloseOnExec(sockfd);  
    #else  
    int sockfd = ::socket(AF_INET,  
                        SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,  
                        IPPROTO_TCP);  
    if (sockfd < 0){  
        printf("socke() error\n");  
    }  
    #endif  
    return sockfd;  
}  
int connect(int sockfd,const struct sockaddr_in& addr){  
    return ::connect(sockfd,sockaddr_cast(&addr),sizeof addr);  
}  
void bindOrDie(int sockfd, const struct sockaddr_in& addr)  
{//bind()  
   int ret = ::bind(sockfd, sockaddr_cast(&addr), sizeof addr);  
     if (ret < 0) {  
         printf("bind() error\n");  
    }  
}  
void listenOrDie(int sockfd){//listen()  
    int ret = ::listen(sockfd, SOMAXCONN);  
    if (ret < 0){  
          printf("listen() error\n");  
    }  
}  
int accept(int sockfd, struct sockaddr_in* addr)  
{//accept()  
    socklen_t addrlen = sizeof *addr;  
    #if VALGRIND  
    int connfd = ::accept(sockfd, sockaddr_cast(addr), &addrlen);  
    setNonBlockAndCloseOnExec(connfd);  
    #else  
    int connfd = ::accept4(sockfd, sockaddr_cast(addr),  
                         &addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);  
    #endif  
    if (connfd < 0){  
        int savedErrno = errno;  
        printf("accept error\n");  
        switch (savedErrno)  
        {  
            case EAGAIN:  
            case ECONNABORTED:  
            case EINTR:  
            case EPROTO: // ???  
            case EPERM:  
            case EMFILE: // per-process lmit of open file desctiptor ???  
                errno = savedErrno;  
                break;  
            case EBADF:  
            case EFAULT:  
            case EINVAL:  
            case ENFILE:  
            case ENOBUFS:  
            case ENOMEM:  
            case ENOTSOCK:  
            case EOPNOTSUPP:  
                printf("accept() fatal erro\n");  
                break;  
            default:  
                printf("accpet() unknown error\n");  
                break;  
        }  
    }  
    return connfd;  
}  
void close(int sockfd){//close()  
    if (::close(sockfd) < 0){  
        printf("sockets::close\n");  
    }  
}  
void shutdownWrite(int sockfd){  
    if(::shutdown(sockfd,SHUT_WR)<0)  
        printf("sockets::shutdownWrite() error\n");  
}  
void toHostPort(char* buf, size_t size,const struct sockaddr_in& addr)  
{//将IPv4地址转为IP和端口  
    char host[INET_ADDRSTRLEN] = "INVALID";  
    ::inet_ntop(AF_INET, &addr.sin_addr, host, sizeof host);  
    uint16_t port =networkToHost16(addr.sin_port);  
    snprintf(buf, size, "%s:%u", host, port);  
}  
void fromHostPort(const char* ip, uint16_t port,struct sockaddr_in* addr)  
{//将主机IP和端口转为IPv4地址  
    addr->sin_family = AF_INET;  
    addr->sin_port = hostToNetwork16(port);  
    if (::inet_pton(AF_INET, ip, &addr->sin_addr) <= 0)  
    {  
        printf("sockets::fromHostPort\n");  
    }  
}  
sockaddr_in getLocalAddr(int sockfd)  
{  
  struct sockaddr_in localaddr;  
  bzero(&localaddr, sizeof localaddr);  
  socklen_t addrlen = sizeof(localaddr);  
  if (::getsockname(sockfd, sockaddr_cast(&localaddr), &addrlen) < 0)  
  {  
      printf("getsockname() error\n");  
  }  
  return localaddr;  
}  
struct sockaddr_in getPeerAddr(int sockfd){  
    struct sockaddr_in peeraddr;  
    bzero(&peeraddr,sizeof peeraddr);  
    socklen_t addrlen=sizeof peeraddr;  
    if(::getpeername(sockfd,sockaddr_cast(&peeraddr),&addrlen)<0)  
        printf("sockets::getPeerAddr() error\n");  
    return peeraddr;  
}  
int getSocketError(int sockfd){  
    int optval;  
    socklen_t optlen=sizeof optval;  
    if(getsockopt(sockfd,SOL_SOCKET,SO_ERROR,&optval,&optlen)<0){  
        return errno;  
    }  
    else{  
        return optval;  
    }  
}  
bool isSelfConnect(int sockfd){//自连接判断  
    struct sockaddr_in localaddr=getLocalAddr(sockfd);  
    struct sockaddr_in peeraddr=getPeerAddr(sockfd);  
    return localaddr.sin_port==peeraddr.sin_port&&  
        localaddr.sin_addr.s_addr==peeraddr.sin_addr.s_addr;  
}  
}//end-namespace  
/* 
 * Socket 
 */  
class InetAddress;  
class Socket:noncopyable{//创建一个socket描述符fd并绑定sockaddr，监听fd功能  
    public:  
        explicit Socket(uint16_t sockfd):sockfd_(sockfd){}  
        ~Socket();  
        int fd() const{return sockfd_;}  
        void bindAddress(const InetAddress& addr);  
        void listen();  
        int accept(InetAddress* peeraddr);  
        void setReuseAddr(bool on);  
        void shutdownWrite(){  
            sockets::shutdownWrite(sockfd_);  
        }  
        void setTcpNoDelay(bool on){  
            int optval=on?1:0;  
            ::setsockopt(sockfd_,IPPROTO_TCP,TCP_NODELAY,&optval,sizeof optval);  
        }  
    private:  
        const int sockfd_;  
};  
/* 
 * sockaddr_in 
 */  
class InetAddress{//sockaddr地址的封装  
    public:  
        explicit InetAddress(uint16_t port);  
        InetAddress(const string& ip,uint16_t port);  
        InetAddress(const struct sockaddr_in& addr):addr_(addr){}  
        string toHostPort() const;  
        const struct sockaddr_in& getSockAddrInet() const{return addr_;}  
        void setSockAddrInet(const struct sockaddr_in& addr){addr_=addr;}  
    private:  
        struct sockaddr_in addr_;  
};  
BOOST_STATIC_ASSERT(sizeof(InetAddress)==sizeof(struct sockaddr_in));//编译时断言  
class Acceptor:noncopyable{//接受TCP连接并执行相应的回调  
    public://Acceptor对应的是一个服务端的监听socket描述符listenfd  
        typedef function<void(int sockfd,const InetAddress&)> NewConnectionCallback;  
        Acceptor(EventLoop* loop,const InetAddress& listenAddr);  
        void setNewConnectionCallback(const NewConnectionCallback& cb)  
        { newConnectionCallback_=cb;}  
        bool listening() const{return listening_;}  
        void listen();  
    private:  
        void handleRead();  
        EventLoop* loop_;  
        Socket acceptSocket_;//服务端listenfd对应RAII封装的socket描述符  
        Channel acceptChannel_;//采用Channel管理服务端监听端口listenfd,可以理解为Channel管理accpetSocket_里的fd  
        NewConnectionCallback newConnectionCallback_;  
        bool listening_;  
  
};  
/* 
 *Socket实现 
 */  
Socket::~Socket()  
{  
    sockets::close(sockfd_);  
}  
void Socket::bindAddress(const InetAddress& addr)  
{  
    sockets::bindOrDie(sockfd_, addr.getSockAddrInet());  
}  
void Socket::listen()  
{  
    sockets::listenOrDie(sockfd_);  
}  
int Socket::accept(InetAddress* peeraddr)  
{  
    struct sockaddr_in addr;  
    bzero(&addr, sizeof addr);  
    int connfd = sockets::accept(sockfd_, &addr);  
    if (connfd >= 0)  
    {  
        peeraddr->setSockAddrInet(addr);  
    }  
    return connfd;  
}  
void Socket::setReuseAddr(bool on)  
{  
    int optval = on ? 1 : 0;  
    ::setsockopt(sockfd_, SOL_SOCKET, SO_REUSEADDR,  
               &optval, sizeof optval);  
}  
/* 
 *InetAddress实现 
 */  
static const in_addr_t kInaddrAny=INADDR_ANY;//任意的网络字节序IP地址为0  
InetAddress::InetAddress(uint16_t port)  
{  
    bzero(&addr_, sizeof addr_);  
    addr_.sin_family = AF_INET;  
    addr_.sin_addr.s_addr = sockets::hostToNetwork32(kInaddrAny);  
    addr_.sin_port = sockets::hostToNetwork16(port);  
}  
InetAddress::InetAddress(const std::string& ip, uint16_t port)  
{  
    bzero(&addr_, sizeof addr_);  
    sockets::fromHostPort(ip.c_str(), port, &addr_);  
}  
string InetAddress::toHostPort() const  
{  
    char buf[32];  
    sockets::toHostPort(buf, sizeof buf, addr_);  
    return buf;  
}  
/* 
 *Acceptor实现 
 */  
Acceptor::Acceptor(EventLoop* loop, const InetAddress& listenAddr)  
  : loop_(loop),  
    acceptSocket_(sockets::createNonblockingOrDie()),  
    acceptChannel_(loop, acceptSocket_.fd()),  
    listening_(false)  
{  
    acceptSocket_.setReuseAddr(true);  
    acceptSocket_.bindAddress(listenAddr);  
    acceptChannel_.setReadCallback(  
      boost::bind(&Acceptor::handleRead, this));  
}  
void Acceptor::listen()  
{  
    loop_->assertInLoopThread();  
    listening_ = true;  
    acceptSocket_.listen();  
    acceptChannel_.enableReading();  
}  
void Acceptor::handleRead()  
{  
    loop_->assertInLoopThread();  
    InetAddress peerAddr(0);  
    int connfd = acceptSocket_.accept(&peerAddr);  
    if (connfd >= 0) {  
        if (newConnectionCallback_) {  
            newConnectionCallback_(connfd, peerAddr);  
        } else {  
            sockets::close(connfd);  
        }  
    }  
}  
/* 
 *Buffer管理数据接收与发送 
 */  
class Buffer{//copyable  
    public:  
        static const size_t kCheapPrepend=8;  
        static const size_t kInitialSize=1024;  
        Buffer():buffer_(kCheapPrepend+kInitialSize),  
            readerIndex_(kCheapPrepend),writerInex_(kCheapPrepend)  
        {  
            assert(readableBytes()==0);  
            assert(writeableBytes()==kInitialSize);  
            assert(prependableBytes()==kCheapPrepend);  
        }  
        void swap(Buffer& rhs){  
            buffer_.swap(rhs.buffer_);  
            std::swap(readerIndex_,rhs.readerIndex_);  
            std::swap(writerInex_,rhs.writerInex_);  
        }  
        size_t readableBytes() const{  
            return writerInex_-readerIndex_;  
        }//返回Buffer中多少数据  
        size_t writeableBytes() const{  
            return buffer_.size()-writerInex_;  
        }//返回还有多少剩余空间  
        size_t prependableBytes() const{  
            return readerIndex_;  
        }//返回可读位置  
        const char* peek() const{  
            return begin()+readerIndex_;  
        }//第一个可读的字节处  
        void retrieve(size_t len){  
            assert(len<=readableBytes());  
            readerIndex_+=len;  
        }//一次性没有读完，readerindex_移动  
        void retrieveUntil(const char* end){  
            assert(peek()<=end);  
            assert(end<=beginWrite());//beginwrite()返回第一个可写的位置  
            retrieve(end-peek());  
        }//返回有多少Buffer中可读字节  
        void retrieveAll(){  
            readerIndex_=kCheapPrepend;  
            writerInex_=kCheapPrepend;  
        }//重置Buffer  
        std::string retrieveAsString(){  
            string str(peek(),readableBytes());  
            retrieveAll();  
            return str;  
        }//以string返回Buffer中数据，并重置Buffer  
        void append(const string& str){  
            append(str.data(),str.length());  
        }  
        void append(const char* data,size_t len){  
            ensureWriteableBytes(len);//空间不足会调用makespace扩容或者内部腾挪  
            std::copy(data,data+len,beginWrite());//copy(Input first,Input last,Output)  
            hasWritten(len);//更新writerinex_  
        }  
        void append(const void* data,size_t len){  
            append(static_cast<const char*>(data),len);  
        }  
        void ensureWriteableBytes(size_t len){  
            if(writeableBytes()<len){  
                makeSpace(len);  
            }//若剩余空间不够，则重新分配空间  
            assert(writeableBytes()>=len);  
        }  
        char* beginWrite(){  
            return begin()+writerInex_;  
        }//可以写的位置  
        const char* beginWrite() const{  
            return begin()+writerInex_;  
        }  
        void hasWritten(size_t len){  
            writerInex_+=len;  
        }//更新writerinex_  
        void prepend(const void* data,size_t len){  
            assert(len<=prependableBytes());  
            readerIndex_-=len;  
            const char* d=static_cast<const char*>(data);  
            std::copy(d,d+len,begin()+readerIndex_);  
        }//前向添加数据  
        void shrink(size_t reserve){  
            vector<char> buf(kCheapPrepend+readableBytes()+reserve);  
            std::copy(peek(),peek()+readableBytes(),buf.begin()+kCheapPrepend);  
            buf.swap(buffer_);  
        }//重置Buffer大小  
        ssize_t readFd(int fd,int* savedErrno){  
            char extrabuf[65536];//栈空间,vector在堆空间  
            struct iovec vec[2];  
            const size_t writeable=writeableBytes();  
            vec[0].iov_base=begin()+writerInex_;  
            vec[0].iov_len=writeable;  
            vec[1].iov_base=extrabuf;  
            vec[1].iov_len=sizeof extrabuf;  
            const ssize_t n=readv(fd,vec,2);//readv集中读  
            if(n<0){  
                *savedErrno=errno;  
            }  
            else if(implicit_cast<size_t>(n)<=writeable){  
                writerInex_+=n;  
            }//Buffer还有剩余  
            else{  
                writerInex_=buffer_.size();  
                append(extrabuf,n-writeable);  
            }//Buffer不够，栈空间数据append到Buffer使Buffer慢慢变大  
            return n;  
        }  
    private:  
        char* begin(){//.>*>&首字符  
            return &*buffer_.begin();  
        }  
        const char* begin() const{  
            return &*buffer_.begin();  
        }  
        void makeSpace(size_t len){//ensurewriteablebytes()->makespace()  
        //当剩余空间writeable()<len时被调用  
            if(writeableBytes()+prependableBytes()<len+kCheapPrepend){  
                buffer_.resize(writerInex_+len);  
            }//(Buffer.size()-writerinex_剩余空间)+(readerindex_第一个可读位置)<  
            //len+前向大小，这时无论怎样腾挪都不够写了，需要追加Buffer的大小  
            else{//可以通过腾挪满足len大小的写入  
                assert(kCheapPrepend<readerIndex_);  
                size_t readable=readableBytes();  
                std::copy(begin()+readerIndex_,begin()+writerInex_,begin()+kCheapPrepend);//Buffer的已有数据向前腾挪  
                readerIndex_=kCheapPrepend;//readerindex_回到初始位置  
                writerInex_=readerIndex_+readable;  
                assert(readable==readableBytes());  
            }  
        }  
    private:  
        vector<char> buffer_;  
        size_t readerIndex_;  
        size_t writerInex_;  
};  
  
class TcpConnection;//表示一个TCP连接  
typedef shared_ptr<TcpConnection> TcpConnectionPtr;//  
/* 
 *TcpConnection 
 */  
class TcpConnection:noncopyable,public enable_shared_from_this<TcpConnection>{  
    public:  
        TcpConnection(EventLoop* loop,const string& name,int sockfd,  
                const InetAddress& localAddr,const InetAddress& peerAddr);  
        ~TcpConnection();  
        EventLoop* getLoop() const{return loop_;}  
        const string& name() const{return name_;}  
        const InetAddress& localAddr(){return localAddr_;}  
        const InetAddress& peerAddress(){return peerAddr_;}  
        bool connected() const{return state_==kConnected;}  
        void send(const string& message);//发送消息,为了线程安全其会调用Tcpconnection::sendInLoop()  
        void shutdown();//关闭TCP连接,为了保证线程安全其会调用Tcpconnection:shutdownInloop()  
        void setTcpNoDelay(bool on);//关闭Nagle算法  
        void setConnectionCallback(const ConnectionCallback& cb){  
            connectionCallback_=cb;  
        }//set*Callback系列函数是由用户通过Tcpserver::set*Callback指定并由TcpServer::newConnection()创建Tcpconnection对象时传递给Tcpconnection::set*Callback函数  
        void setMessageCallback(const MessageCallback& cb){  
            messageCallback_=cb;  
        }  
        void setWriteCompleteCallback(const WriteCompleteCallback& cb){  
            writeCompleteCallback_=cb;  
        }  
        void setCloseCallback(const CloseCallback& cb){  
        //由TcpServer和TcpClient调用，解除它们中的TcpConnectionPtr  
            closeCallback_=cb;  
        }  
        void connectEstablished();//调用Channel::enableReading()向Poller事件表注册事件，并调用TcpConnection::connectionCallback_()完成用户指定的连接回调  
        //Acceptor::handleRead()->TcpServer::newConnection()->TcpConnection::connectEstablished()  
        void connectDestroyed();//连接销毁函数,调用Channel::diableAll()使Poller对sockfd_忽略，并调用Eventloop::removeChannel()移除sockfd_对应的Channel  
        //TcpServer::removeConnection()->EventLoop::runInLoop()->TcpServer::removeConnectionInLoop()->EventLoop::queueInLoop()->TcpConnection::connectDestroyed()  
        //这是TcpConenction析构前调用的最后一个函数，用于告诉用户连接已断开  
        //将TcpConenction状态置为kDisconnected,Channel::diableAll(),connectioncallback_(),EventLoop::removeChannel()  
    private:  
        enum StateE{kConnecting,kConnected,kDisconnecting,kDisconnected,};  
        //Tcpconnection有四个状态:正在连接，已连接，正在断开，已断开  
        void setState(StateE s){state_=s;}  
        void handleRead();  
        //Tcpconnection::handle*系列函数是由Poller返回sockfd_上就绪事件后由Channel::handelEvent()调用的就绪事件回调函数  
        void handleWrite();  
        void handleClose();  
        void handleError();  
        void sendInLoop(const string& message);  
        void shutdownInLoop();  
        EventLoop* loop_;  
        string name_;  
        StateE state_;  
        scoped_ptr<Socket> socket_;//TcpConnection对应的那个TCP客户连接封装为socket_  
        scoped_ptr<Channel> channel_;//TcpConnection对应的TCP客户连接connfd采用Channel管理  
        InetAddress localAddr_;//TCP连接对应的服务端地址  
        InetAddress peerAddr_;//TCP连接的客户端地址  
        ConnectionCallback connectionCallback_;  
        //用户指定的连接回调函数,TcpServer::setConenctionCallback()->Acceptor::handleRead()->Tcpserver::newConnection()->TcpConnection::setConnectionCallback()  
        //即TcpServer::setConenctionCallback()接收用户注册的连接回调，并通过Acceptor::handleRead()->Tcpserver::newConnection()将此用户连接回调函数传给Tcpconnection  
        MessageCallback messageCallback_;//用户指定的消息处理函数，也是经由Tcpserver传给Tcpconnection  
        WriteCompleteCallback writeCompleteCallback_;  
        CloseCallback closeCallback_;  
        Buffer inputBuffer_;  
        Buffer outputBuffer_;  
};  
/* 
 *Tcpserver 
 */  
class TcpServer:noncopyable{//管理所有的TCP连接  
    public:  
        TcpServer(EventLoop* loop,const InetAddress& listenAddr);//构造时就有个监听端口的地址  
        ~TcpServer();  
        void setThreadNum(int numThreads);  
        void start();  
        void setConnectionCallback(const ConnectionCallback& cb){  
            connectionCallback_=cb;  
        }//TCP客户连接回调在TcpConnection里，TcpConnection::connectEstablished()->TcpConnection::connectionCallback_()  
        void setMessageCallback(const MessageCallback& cb){  
            messageCallback_=cb;  
        }//此回调将传给TcpConnection::setMessageCallback()作为TcpConenction的消息回调  
        void setWriteCompleteCallback(const WriteCompleteCallback& cb){  
            writeCompleteCallback_=cb;  
        }  
    private:  
        void newConnection(int sockfd,const InetAddress& peerAddr);  
        void removeConnection(const TcpConnectionPtr& conn);  
        void removeConnectionInLoop(const TcpConnectionPtr& conn);  
        typedef map<string,TcpConnectionPtr> ConnectionMap;  
        EventLoop* loop_;  
        const string name_;  
        scoped_ptr<Acceptor> acceptor_;//监听端口接受连接  
        scoped_ptr<EventLoopThreadPool> threadPool_;//开启EventLoopThreadPool管理TCP连接  
        ConnectionCallback connectionCallback_;//传给TcpConnection::setConnectionCallback(connectioncallback_)  
        MessageCallback messageCallback_;//传给TcpConnection::setMessageCallback(messagecallback_)  
        WriteCompleteCallback writeCompleteCallback_;  
        bool started_;  
        int nextConnId_;//用于标识TcpConnection，name_+nextConnId_就构成了一个TcpConnection的名字  
        ConnectionMap connections_;//该TcpServer管理的所有TCP客户连接存放的容器  
};  
/* 
 *TcpConnection实现 
 */  
TcpConnection::TcpConnection(EventLoop* loop,  
                             const std::string& nameArg,  
                             int sockfd,  
                             const InetAddress& localAddr,  
                             const InetAddress& peerAddr)  
    : loop_(loop),  
    name_(nameArg),  
    state_(kConnecting),  
    socket_(new Socket(sockfd)),  
    channel_(new Channel(loop, sockfd)),  
    localAddr_(localAddr),  
    peerAddr_(peerAddr)  
{  
    channel_->setReadCallback(bind(&TcpConnection::handleRead, this));  
    channel_->setWriteCallback(bind(&TcpConnection::handleWrite,this));  
    channel_->setCloseCallback(bind(&TcpConnection::handleClose,this));  
    channel_->setErrorCallback(bind(&TcpConnection::handleError,this));  
}  
TcpConnection::~TcpConnection()  
{  
    printf("TcpConnection::%s,fd=%d\n",name_.c_str(),channel_->fd());  
}  
void TcpConnection::send(const string& message){  
    cout<<"TcpConnection::send() ##"<<message<<endl;  
    if(state_==kConnected){  
        if(loop_->isInLoopThread()){  
            sendInLoop(message);  
        }  
        else{  
            loop_->runInLoop(bind(&TcpConnection::sendInLoop,this,message));  
        }  
    }  
}  
void TcpConnection::sendInLoop(const string& message){  
    //若TcpConnection的socket已经注册了可写事件即outputBuffer_已经有数据了则直接调用Buffer::append  
    //若socket的Channel没有注册可读则表明outputbuffer_没有数据存留，则可以直接先write发送  
    //若write一次性没有发送完，则剩下数据需要append到outputbuffer_  
    //若write一次性发送完毕则需要执行writecompletecallback_  
    loop_->assertInLoopThread();  
    ssize_t nwrote=0;  
    cout<<message<<endl;  
    if(!channel_->isWriting()&&outputBuffer_.readableBytes()==0){  
        nwrote=write(channel_->fd(),message.data(),message.size());  
        if(nwrote>=0){  
            if(implicit_cast<size_t>(nwrote)<message.size()){  
                printf("I am going to write more data\n");  
            }  
            else if(writeCompleteCallback_){  
                loop_->queueInLoop(bind(writeCompleteCallback_,shared_from_this()));  
            }  
        }  
        else{  
            nwrote=0;  
            if(errno!=EWOULDBLOCK){  
                printf("TcpConnection::sendInLoop() error\n");  
            }  
        }  
    }  
    assert(nwrote>=0);  
    if(implicit_cast<size_t>(nwrote)<message.size()){  
        outputBuffer_.append(message.data()+nwrote,message.size()-nwrote);  
        if(!channel_->isWriting()){  
           channel_->enableWriting();  
        }  
    }  
}  
void TcpConnection::shutdown(){  
    if(state_==kConnected){  
        setState(kDisconnecting);  
        loop_->runInLoop(bind(&TcpConnection::shutdownInLoop,this));  
    }  
}  
void TcpConnection::shutdownInLoop(){  
    loop_->assertInLoopThread();  
    if(!channel_->isWriting()){  
        socket_->shutdownWrite();  
    }  
}  
void TcpConnection::setTcpNoDelay(bool on){  
    socket_->setTcpNoDelay(on);  
}  
void TcpConnection::connectEstablished()  
{  
    loop_->assertInLoopThread();  
    assert(state_ == kConnecting);  
    setState(kConnected);  
    channel_->enableReading();  
    connectionCallback_(shared_from_this());//连接建立回调函数  
}  
void TcpConnection::handleRead()  
{  
    int savedErrno=0;  
    ssize_t n =inputBuffer_.readFd(channel_->fd(),&savedErrno);//readv()  
    if(n>0)  
        messageCallback_(shared_from_this(),&inputBuffer_);  
    else if(n==0)  
        handleClose();  
    else{  
        errno=savedErrno;  
        printf("TcpConnection::hanleRead() error\n");  
        handleError();  
    }  
}  
void TcpConnection::handleWrite(){  
    loop_->assertInLoopThread();  
    if(channel_->isWriting()){  
        ssize_t n=write(channel_->fd(),outputBuffer_.peek(),outputBuffer_.readableBytes());  
        if(n>0){//peek()返回第一个可读的字节，readablebytes()返回Buffer中数据的大小  
            outputBuffer_.retrieve(n);//readerindex_+=n更新Buffer的读位置  
            if(outputBuffer_.readableBytes()==0){//如果Buffer里还有数据未发送的话不会立即调用shutdownwrite而是等待数据发送完毕再shutdown  
                channel_->disableWriting();//防止busy loop  
                if(writeCompleteCallback_){  
                    loop_->queueInLoop(bind(writeCompleteCallback_,shared_from_this()));  
                }  
                if(state_==kDisconnecting)  
                    shutdownInLoop();  
            }  
            else  
                printf("I am going to write more data\n");  
        }  
        else  
            printf("TcpConnection::handleWrite()\n");  
    }  
    else  
        printf("Connection is down,no more writing\n");  
}  
void TcpConnection::handleClose(){  
    loop_->assertInLoopThread();  
    assert(state_==kConnected||state_==kDisconnecting);  
    channel_->disableAll();  
    closeCallback_(shared_from_this());  
}  
void TcpConnection::handleError(){  
    int err=sockets::getSocketError(channel_->fd());  
    printf("TcpConnection::handleError() %d %s\n",err,strerror(err));  
}  
void TcpConnection::connectDestroyed(){  
    loop_->assertInLoopThread();  
    printf("TcpConnection::handleClose() state=%s\n",state_);  
    assert(state_==kConnected||state_==kDisconnected);  
    setState(kDisconnected);  
    channel_->disableAll();  
    connectionCallback_(shared_from_this());  
    loop_->removeChannel(get_pointer(channel_));  
}  
/* 
 *TcpServer实现 
 */  
TcpServer::TcpServer(EventLoop* loop, const InetAddressEventLoop::removeChannel()  
    name_(listenAddr.toHostPort()),  
    acceptor_(new Acceptor(loop, listenAddr)),  
    threadPool_(new EventLoopThreadPool(loop)),  
    started_(false),  
    nextConnId_(1))  
{  
    acceptor_->setNewConnectionCallback(bind(&TcpServer::newConnection, this, _1, _2));  
}  
TcpServer::~TcpServer()  
{  
}  
void TcpServer::setThreadNum(int numThreads){  
    assert(numThreads>=0);  
    threadPool_->setThreadNum(numThreads);  
}  
void TcpServer::start()  
{  
    if (!started_)  
    {  
        started_ = true;  
    }  
  
    if (!acceptor_->listening())  
    {  
        loop_->runInLoop(bind(&Acceptor::listen, get_pointer(acceptor_)));  
    }//通过EventLoop监听服务端的listenfd,shared_ptr.hpp中的get_pointer用于返回shared_ptr所管理对象的裸指针  
}  
void TcpServer::newConnection(int sockfd, const InetAddress& peerAddr)  
{//用于Acceptor接受一个连接后通过此回调通知使用者  
    loop_->assertInLoopThread();  
    char buf[32];  
    snprintf(buf, sizeof buf, "#%d", nextConnId_);  
    ++nextConnId_;  
    string connName = name_ + buf;  
    InetAddress localAddr(sockets::getLocalAddr(sockfd));  
    EventLoop* ioLoop=threadPool_->getNextLoop();//选一个EventLoop给TcpConnection  
    TcpConnectionPtr conn(  
      new TcpConnection(ioLoop, connName, sockfd, localAddr, peerAddr));  
    connections_[connName]=conn;  
    conn->setConnectionCallback(connectionCallback_);//传递给TcpConnection  
    conn->setMessageCallback(messageCallback_);  
    conn->setWriteCompleteCallback(writeCompleteCallback_);  
    conn->setCloseCallback(bind(&TcpServer::removeConnection,this,_1));//将移除TcpConnectionPtr的操作注册到TcpConnection::setCloseCallback  
    ioLoop->runInLoop(bind(&TcpConnection::connectEstablished,conn));  
    //通过EventLoop::runInLoop()->EventLoop::queueInLoop()->TcpConnection::connectEstablished()  
}  
void TcpServer::removeConnection(const TcpConnectionPtr& conn){  
    loop_->runInLoop(bind(&TcpServer::removeConnectionInLoop,this,conn));  
    //TcpServer::removeConnection()->EventLoop::runInLoop()->EventLoop::queueInLoop()->TcpServer::removeConnectionInLoop()  
}  
void TcpServer::removeConnectionInLoop(const TcpConnectionPtr& conn){  
    loop_->assertInLoopThread();  
    size_t n=connections_.erase(conn->name());  
    assert(n==1);  
    (void)n;  
    EventLoop* ioLoop=conn->getLoop();  
    ioLoop->queueInLoop(bind(&TcpConnection::connectDestroyed,conn));//在IO线程内完成直接EventLoop::queueInLoop()  
}  
/* 
 * 发起连接 
 */  
class Connector : boost::noncopyable  
{  
    public:  
        typedef function<void (int sockfd)> NewConnectionCallback;  
        Connector(EventLoop* loop, const InetAddress& serverAddr);  
        ~Connector();  
        void setNewConnectionCallback(const NewConnectionCallback& cb)  
        { newConnectionCallback_ = cb; }  
        void start();  // can be called in any thread  
        void restart();  // must be called in loop thread  
        void stop();  // can be called in any thread  
        const InetAddress& serverAddress() const { return serverAddr_; }  
    private:  
        enum States { kDisconnected, kConnecting, kConnected };  
        //未连接，正在连接，已连接  
        static const int kMaxRetryDelayMs = 30*1000;  
        static const int kInitRetryDelayMs = 500;  
        void setState(States s) { state_ = s; }  
        void startInLoop();  
        void connect();  
        void connecting(int sockfd);  
        void handleWrite();  
        void handleError();  
        void retry(int sockfd);  
        int removeAndResetChannel();  
        void resetChannel();  
        EventLoop* loop_;  
        InetAddress serverAddr_;  
        bool connect_; // atomic  
        States state_;  // FIXME: use atomic variable  
        boost::scoped_ptr<Channel> channel_;  
        NewConnectionCallback newConnectionCallback_;  
        int retryDelayMs_;  
        TimerId timerId_;  
};  
/* 
 * Connector实现 
 */  
typedef boost::shared_ptr<Connector> ConnectorPtr;  
const int Connector::kMaxRetryDelayMs;  
Connector::Connector(EventLoop* loop, const InetAddress& serverAddr)  
    :loop_(loop),  
    serverAddr_(serverAddr),  
    connect_(false),  
    state_(kDisconnected),  
    retryDelayMs_(kInitRetryDelayMs)  
{  
}  
Connector::~Connector()  
{  
    loop_->cancel(timerId_);  
    assert(!channel_);  
}  
void Connector::start()  
{//可以由其它线程调用  
    connect_ = true;  
    loop_->runInLoop(boost::bind(&Connector::startInLoop, this)); // FIXME: unsafe  
}  
void Connector::startInLoop()  
{  
    loop_->assertInLoopThread();  
    assert(state_ == kDisconnected);  
    if (connect_)  
    {  
        connect();//  
    }  
    else  
    {}  
}  
void Connector::connect()  
{  
    int sockfd = sockets::createNonblockingOrDie();  
    int ret = sockets::connect(sockfd, serverAddr_.getSockAddrInet());  
    int savedErrno = (ret == 0) ? 0 : errno;  
    switch (savedErrno)  
    {  
        case 0:  
        case EINPROGRESS:  
        case EINTR:  
        case EISCONN:  
            connecting(sockfd);  
            break;  
  
        case EAGAIN:  
        case EADDRINUSE:  
        case EADDRNOTAVAIL:  
        case ECONNREFUSED:  
        case ENETUNREACH:  
            retry(sockfd);  
            break;  
  
        case EACCES:  
        case EPERM:  
        case EAFNOSUPPORT:  
        case EALREADY:  
        case EBADF:  
        case EFAULT:  
        case ENOTSOCK:  
            sockets::close(sockfd);  
            break;  
  
        default:  
            sockets::close(sockfd);  
            // connectErrorCallback_();  
            break;  
  }  
}  
void Connector::restart()  
{  
    loop_->assertInLoopThread();  
    setState(kDisconnected);  
    retryDelayMs_ = kInitRetryDelayMs;  
    connect_ = true;  
    startInLoop();  
}  
void Connector::stop()  
{  
    connect_ = false;  
    loop_->cancel(timerId_);  
}  
void Connector::connecting(int sockfd)  
{//EINPROGRESS  
    setState(kConnecting);  
    assert(!channel_);  
    channel_.reset(new Channel(loop_, sockfd));  
    channel_->setWriteCallback(bind(&Connector::handleWrite, this)); // FIXME: unsafe  
    channel_->setErrorCallback(bind(&Connector::handleError, this)); // FIXME: unsafe  
    channel_->enableWriting();  
}  
int Connector::removeAndResetChannel()  
{  
    channel_->disableAll();  
    loop_->removeChannel(get_pointer(channel_));  
    int sockfd = channel_->fd();  
    loop_->queueInLoop(bind(&Connector::resetChannel, this)); // FIXME: unsafe  
    return sockfd;  
}  
void Connector::resetChannel()  
{  
    channel_.reset();  
}  
void Connector::handleWrite()  
{  
    if (state_ == kConnecting)  
    {  
        int sockfd = removeAndResetChannel();  
        int err = sockets::getSocketError(sockfd);  
        if (err)  
            retry(sockfd);  
        else if (sockets::isSelfConnect(sockfd))  
            retry(sockfd);  
        else  
        {  
            setState(kConnected);  
            if (connect_)  
                newConnectionCallback_(sockfd);  
            else  
                sockets::close(sockfd);  
        }  
    }  
    else  
    {  
        assert(state_ == kDisconnected);  
    }  
}  
  
void Connector::handleError()  
{  
    assert(state_ == kConnecting);  
  
    int sockfd = removeAndResetChannel();  
    int err = sockets::getSocketError(sockfd);  
    retry(sockfd);  
}  
  
void Connector::retry(int sockfd)  
{//EAGAIN  
    sockets::close(sockfd);  
    setState(kDisconnected);  
    if (connect_){  
        timerId_ = loop_->runAfter(retryDelayMs_/1000.0,  // FIXME: unsafe  
                               boost::bind(&Connector::startInLoop, this));  
        retryDelayMs_ = std::min(retryDelayMs_ * 2, kMaxRetryDelayMs);  
    }  
    else  
    {}  
}  
/* 
 * TcpClient 
 */  
typedef boost::shared_ptr<Connector> ConnectorPtr;  
class TcpClient : boost::noncopyable  
{  
    public:  
        TcpClient(EventLoop* loop,  
            const InetAddress& serverAddr,  
            const string& name);  
     ~TcpClient();  // force out-line dtor, for scoped_ptr members.  
        void connect();  
        void disconnect();  
        void stop();  
        TcpConnectionPtr connection() const  
        {  
            MutexLockGuard lock(mutex_);  
            return connection_;  
        }  
  
        EventLoop* getLoop() const { return loop_; }  
        bool retry() const;  
        void enableRetry() { retry_ = true; }  
        void setConnectionCallback(const ConnectionCallback& cb)  
        { connectionCallback_ = cb; }  
        void setMessageCallback(const MessageCallback& cb)  
        { messageCallback_ = cb; }  
        void setWriteCompleteCallback(const WriteCompleteCallback& cb)  
        { writeCompleteCallback_ = cb; }  
        #ifdef __GXX_EXPERIMENTAL_CXX0X__  
        void setConnectionCallback(ConnectionCallback&& cb)  
        { connectionCallback_ = cb; }  
        void setMessageCallback(MessageCallback&& cb)  
        { messageCallback_ = cb; }  
        void setWriteCompleteCallback(WriteCompleteCallback&& cb)  
        { writeCompleteCallback_ = cb; }  
        #endif  
    private:  
        void newConnection(int sockfd);  
        void removeConnection(const TcpConnectionPtr& conn);  
        EventLoop* loop_;  
        ConnectorPtr connector_; // avoid revealing Connector  
        const string name_;  
        ConnectionCallback connectionCallback_;  
        MessageCallback messageCallback_;  
        WriteCompleteCallback writeCompleteCallback_;  
        bool retry_;   // atmoic  
        bool connect_; // atomic  
        int nextConnId_;  
        mutable MutexLock mutex_;  
        TcpConnectionPtr connection_; // @BuardedBy mutex_  
};  
namespace detail  
{  
    void removeConnection(EventLoop* loop, const TcpConnectionPtr& conn)  
    {  
      loop->queueInLoop(boost::bind(&TcpConnection::connectDestroyed, conn));  
    }  
    void removeConnector(const ConnectorPtr& connector)  
    {  
      //connector->  
    }  
}  
TcpClient::TcpClient(EventLoop* loop,  
                     const InetAddress& serverAddr,  
                     const string& name)  
  : loop_(CHECK_NOTNULL(loop)),  
    connector_(new Connector(loop, serverAddr)),  
    name_(name),  
    connectionCallback_(defaultConnectionCallback),  
    messageCallback_(defaultMessageCallback),  
    retry_(false),  
    connect_(true),  
    nextConnId_(1)  
{  
    connector_->setNewConnectionCallback(  
      boost::bind(&TcpClient::newConnection, this, _1));  
}  
  
TcpClient::~TcpClient()  
{  
    TcpConnectionPtr conn;  
    {  
        MutexLockGuard lock(mutex_);  
        conn = connection_;  
    }  
    if (conn)  
    {  
        CloseCallback cb = boost::bind(&detail::removeConnection, loop_, _1);  
        loop_->runInLoop(  
            boost::bind(&TcpConnection::setCloseCallback, conn, cb));  
    }  
    else  
    {  
        connector_->stop();  
        loop_->runAfter(1, boost::bind(&detail::removeConnector, connector_));  
    }  
}  
void TcpClient::connect()  
{  
    connect_ = true;  
    connector_->start();  
}  
void TcpClient::disconnect()  
{  
    connect_ = false;  
    {  
        MutexLockGuard lock(mutex_);  
        if (connection_)  
        {  
            connection_->shutdown();  
        }  
    }  
}  
void TcpClient::stop()  
{  
    connect_ = false;  
    connector_->stop();  
}  
void TcpClient::newConnection(int sockfd)  
{  
    loop_->assertInLoopThread();  
    InetAddress peerAddr(sockets::getPeerAddr(sockfd));  
    char buf[32];  
    snprintf(buf, sizeof buf, ":%s#%d", peerAddr.toIpPort().c_str(), nextConnId_);  
    ++nextConnId_;  
    string connName = name_ + buf;  
    InetAddress localAddr(sockets::getLocalAddr(sockfd));  
    TcpConnectionPtr conn(new TcpConnection(loop_,  
                                          connName,  
                                          sockfd,  
                                          localAddr,  
                                          peerAddr));  
  
    conn->setConnectionCallback(connectionCallback_);  
    conn->setMessageCallback(messageCallback_);  
    conn->setWriteCompleteCallback(writeCompleteCallback_);  
    conn->setCloseCallback(  
      boost::bind(&TcpClient::removeConnection, this, _1)); // FIXME: unsafe  
    {  
        MutexLockGuard lock(mutex_);  
        connection_ = conn;  
    }  
    conn->connectEstablished();  
}  
void TcpClient::removeConnection(const TcpConnectionPtr& conn)  
{  
    loop_->assertInLoopThread();  
    assert(loop_ == conn->getLoop());  
    {  
        MutexLockGuard lock(mutex_);  
        assert(connection_ == conn);  
        connection_.reset();  
    }  
    loop_->queueInLoop(boost::bind(&TcpConnection::connectDestroyed, conn));  
    if (retry_ && connect_)  
    {  
        connector_->restart();  
    }  
}  
  
/* 
 *Epoll 
 */  
class Epoller:noncopyable{  
    public:  
        typedef vector<Channel*> ChannelList;  
        Epoller(EventLoop* loop)  
            :ownerLoop_(loop),  
            epollfd_(::epoll_create1(EPOLL_CLOEXEC)),  
            events_(kInitEventListSize)  
        {  
            if(epollfd_<0){  
                printf("Epoller::epoll_create1() error\n");  
                abort();  
            }  
        }  
        ~Epoller(){  
            ::close(epollfd_);  
        }  
        Timestamp poll(int timeoutMs,ChannelList* activeChannels){  
            int numEvents=::epoll_wait(epollfd_,&*events_.begin(),  
                    static_cast<int>(events_.size()),timeoutMs);  
            Timestamp now(Timestamp::now());  
            if(numEvents>0){  
                fillActiveChannels(numEvents,activeChannels);  
                if(implicit_cast<size_t>(numEvents)==events_.size()){  
                    events_.resize(events_.size()*2);  
                }  
                else if(numEvents==0){}  
                else{  
                    printf("Epoller::epoll_wait() error\n");  
                }  
            }  
            return now;  
        }  
        void updateChannel(Channel* channel){  
            assertInLoopThread();  
            const int index=channel->index();  
            if(index==-1||index==2){  
                int fd=channel->fd();  
                if(index==-1){  
                    assert(channels_.find(fd)==channels_.end());  
                    channels_[fd]=channel;  
                }  
                else{  
                    assert(channels_.find(fd)!=channels_.end());  
                    assert(channels_[fd]==channel);  
                }  
                channel->set_index(1);  
                update(EPOLL_CTL_ADD,channel);  
            }  
            else{  
                int fd=channel->fd();  
                (void)fd;  
                assert(channels_.find(fd)!=channels_.end());  
                assert(channels_[fd]==channel);  
                assert(index==1);  
                if(channel->isNoneEvent()){  
                    update(EPOLL_CTL_DEL,channel);  
                    channel->set_index(2);  
                }  
                else{  
                    update(EPOLL_CTL_MOD,channel);  
                }  
            }  
        }  
        void removeChannel(Channel* channel){  
            assertInLoopThread();  
            int fd=channel->fd();  
            assert(channels_.find(fd)!=channels_.end());  
            assert(channels_[fd]==channel);  
            assert(channel->isNoneEvent());  
            int index=channel->index();  
            assert(index==1||index==2);  
            size_t n=channels_.erase(fd);  
            (void)n;  
            assert(n==1);  
            if(index==1){  
                update(EPOLL_CTL_DEL,channel);  
            }  
            channel->set_index(-1);  
        }  
        void assertInLoopThread(){  
            ownerLoop_->assertInLoopThread();  
        }  
    private:  
        static const int kInitEventListSize=16;  
        void fillActiveChannels(int numEvents,ChannelList* activeChannels) const  
        {  
            assert(implicit_cast<size_t>(numEvents)<=events_.size());  
            for(int i=0;i<numEvents;i++){  
                Channel* channel=static_cast<Channel*>(events_[i].data.ptr);  
                int fd=channel->fd();  
                ChannelMap::const_iterator it=channels_.find(fd);  
                assert(it!=channels_.end());  
                assert(it->second==channel);  
                channel->set_revents(events_[i].events);  
                activeChannels->push_back(channel);  
            }  
        }  
        void update(int operation,Channel* channel){  
            struct epoll_event event;  
            bzero(&event,sizeof event);  
            event.events=channel->events();  
            event.data.ptr=channel;  
            int fd=channel->fd();  
            if(::epoll_ctl(epollfd_,operation,fd,&event)<0){  
                if(operation==EPOLL_CTL_DEL){  
                    printf("Epoller::update() EPOLL_CTL_DEL error\n");  
                }  
                else{  
                    printf("Epoller::update() EPOLL_CTL_ error\n");  
                }  
            }  
        }  
        typedef vector<struct epoll_event> EventList;  
        typedef map<int,Channel*> ChannelMap;  
  
        EventLoop* ownerLoop_;  
        int epollfd_;  
        EventList events_;  
        ChannelMap channels_;  
};  
