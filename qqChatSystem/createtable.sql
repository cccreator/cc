CREATE SEQUENCE seq1
increment by 1
start with 1
maxvalue 99999999999;


CREATE TABLE baidu 
(ID int NOT NULL,
url varchar2(100), name varchar(100),
description varchar2(200));

CREATE UNIQUE INDEX baidu_id
ON baidu (ID);

CREATE INDEX baidu_name
ON baidu (name);

