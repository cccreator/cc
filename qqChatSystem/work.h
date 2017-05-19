/*
 * work.h
 *
 *  Created on: 2013年12月17日
 *      Author: zhujy
 */

#ifndef WORK_H_
#define WORK_H_

void gethttpcommand(const char *sHTTPMsg, char *command); //从http请求中读出GET后面的命令行
int gettempletcontent(char *buf); //得到模板文件templet.html的内容
int getdynamicccontent(const char *query, char **buf); //动态设置http请求内容
int make_http_content(const char *command, char **buf); //根据get提供的文件名，生成静态http reponse消息内容
void *socket_contr(void *arg);

#endif /* WORK_H_ */
