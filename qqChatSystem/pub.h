/*
 * pub.h
 *
 *  Created on: 2013年12月17日
 *      Author: zhujy
 */

#ifndef PUB_H_
#define PUB_H_


void setdaemon();
void catch_Signal(int Sign);
int signal1(int signo, void (*func)(int));
int hex2dec(const char hex); //将16进制的字符转化为十进制的整数
unsigned char hexstr2dec(const char *hex); //将16进制的字符串转化为十进制的unsigned char
//将HTTP GET请求中的转义符号转化为标准字符,注意，空格被转义为'+'号
void httpstr2stdstr(const char *httpstr, char *stdstr);
const char *getfiletype(const char *filename); //根据扩展名返回文件类型描述
int getfilecontent(const char *filename, char **buf); //得到文件内容
int socket_create(int port);
void socket_accept(int st);

#endif /* PUB_H_ */
