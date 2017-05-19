/*
 * myoracle.h
 *
 *  Created on: 2014-2-17
 *      Author: zhujy
 */
#ifndef MYORACLE_H_
#define MYORACLE_H_

int sql_connect(const char *User, const char *Password, const char *DBName);
int sql_disconnect();
int query_result(const char *name, char **buf);

#endif /* MYORACLE_H_ */
