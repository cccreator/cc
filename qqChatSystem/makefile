.SUFFIXES: .c .o

CC=gcc
PROC=proc

ORACLE_HOME=/opt/oracle/product/11.2.0
ORAFLAGS1=/usr/include/linux
ORAFLAGS2=/usr/lib/gcc/i686-redhat-linux/4.4.4/include

PROCSRCS=myoracle.pc
DBSRCS=$(PROCSRCS:.pc=.c)

SRCS=server.c\
		pub.c\
		work.c\
		$(DBSRCS)
		
OBJS=$(SRCS:.c=.o)
EXEC=myhttpd

ORCFLAGS1=-L${ORACLE_HOME}/lib
ORCFLAGS2=-lclntsh

all: $(OBJS)
	$(CC) -o $(EXEC) $(OBJS) -lpthread $(ORCFLAGS1) $(ORCFLAGS2)
	@echo '-------------ok--------------'

.c.o: $(DBSRCS)
	$(CC) -Wall -g -o $@ -c $<
	
$(DBSRCS):
	${PROC} INAME=$(PROCSRCS) INCLUDE=$(ORAFLAGS1) INCLUDE=$(ORAFLAGS2) CPOOL=YES MODE=ANSI CODE=ANSI_C PARSE=PARTIAL THREADS=YES ONAME=$(DBSRCS)

clean:
	rm -f $(OBJS)
	rm -f $(DBSRCS)
	rm -f core*

