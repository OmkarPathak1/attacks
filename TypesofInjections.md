### 1. **SQL Injection (SQLi)**

**Description**:  
SQL Injection is a code injection technique that exploits vulnerabilities in an application's software by inserting or "injecting" malicious SQL statements into an entry field, allowing attackers to manipulate the backend database.

**Example**:
Suppose a login form has the following SQL query:
```sql
SELECT * FROM users WHERE username = 'user_input' AND password = 'user_input';
```
If the input is not sanitized, an attacker can input:
```sql
' OR '1'='1
```
The resulting SQL query would look like this:
```sql
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = '';
```
This query always returns `true`, granting unauthorized access.

**Potential Impacts**:
- Unauthorized access to user data.
- Data manipulation (e.g., altering or deleting data).
- Data leakage or extraction.
- Complete system compromise.

**Prevention**:
- Use parameterized queries (prepared statements).
- Employ ORM (Object-Relational Mapping) libraries.
- Sanitize and validate user inputs.
- Use web application firewalls (WAFs).

### 2. **Command Injection**

**Description**:  
Command Injection is an attack where the goal is to execute arbitrary commands on the host operating system via a vulnerable application. It occurs when an application passes unsafe user-supplied data to a system shell.

**Example**:
If a web application uses the following code to execute a system command:
```python
os.system("ping " + user_input)
```
An attacker can input:
```
8.8.8.8; rm -rf /
```
The command executed would be:
```shell
ping 8.8.8.8; rm -rf /
```
This could result in the deletion of all files in the root directory.

**Potential Impacts**:
- Unauthorized access to the underlying operating system.
- Execution of arbitrary commands.
- Data loss, system compromise, and complete control of the server.

**Prevention**:
- Avoid using system calls; prefer safer APIs or libraries.
- Sanitize and validate all user inputs.
- Use allowlists for expected command inputs.

### 3. **LDAP Injection**

**Description**:  
LDAP (Lightweight Directory Access Protocol) Injection is an attack used to exploit web applications that construct LDAP statements based on user input. Similar to SQL Injection, an attacker can manipulate queries to access unauthorized data.

**Example**:
Consider the following LDAP query:
```ldap
(&(uid=user_input)(userPassword=user_input))
```
An attacker could input:
```ldap
*)(uid=*))(|(uid=* 
```
The query becomes:
```ldap
(&(uid=*)(uid=*))(|(uid=*)
```
This would grant access without proper credentials.

**Potential Impacts**:
- Unauthorized access to sensitive information stored in LDAP directories.
- Manipulation of directory content.

**Prevention**:
- Use parameterized LDAP queries.
- Validate and sanitize user input.
- Apply principle of least privilege.

### 4. **XML Injection (XXE - XML External Entity Injection)**

**Description**:  
XML Injection exploits vulnerabilities in applications that parse XML input. An attacker can inject malicious XML code into the input, potentially allowing access to files on the server.

**Example**:
If an XML parser accepts external entities and the input is not sanitized, the attacker could send:
```xml
<!DOCTYPE foo [  
  <!ELEMENT foo ANY >  
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>  
<foo>&xxe;</foo>
```
This results in the content of `/etc/passwd` being displayed.

**Potential Impacts**:
- Access to sensitive server files.
- Remote code execution.
- Denial of Service (DoS).

**Prevention**:
- Disable DTDs (Document Type Definitions) when parsing XML.
- Use libraries that protect against XXE.
- Validate and sanitize XML input.

### 5. **XPath Injection**

**Description**:  
XPath Injection is similar to SQL Injection but targets XML data by manipulating XPath queries. It allows an attacker to bypass authentication and access data from an XML database.

**Example**:
A vulnerable XPath query:
```xpath
"//users/user[username/text()=' " + user_input + " ' and password/text()=' " + password_input + " ']"
```
An attacker can input:
```xpath
' or '1'='1
```
Which modifies the query to:
```xpath
"//users/user[username/text()='' or '1'='1' and password/text()=' ']"
```
This would always evaluate to true.

**Potential Impacts**:
- Unauthorized data access.
- Data manipulation or deletion.

**Prevention**:
- Use parameterized queries for XPath.
- Validate and sanitize all user inputs.
- Avoid dynamic XPath expressions.

### 6. **JSON Injection**

**Description**:  
JSON Injection happens when user-provided data is not correctly sanitized and directly incorporated into JSON data structures. This can lead to data manipulation or unauthorized access.

**Example**:
If a JavaScript code concatenates user input directly:
```javascript
var data = '{"user": "' + userInput + '"}';
```
An attacker can input:
```json
"}; alert('Hacked'); var a = {"
```
This would result in the code being executed.

**Potential Impacts**:
- Cross-site scripting (XSS).
- Manipulation of client-side data.

**Prevention**:
- Always use secure methods for generating JSON.
- Validate and sanitize user inputs.
- Use libraries that handle JSON encoding/decoding securely.

### 7. **Host Header Injection**

**Description**:  
Host Header Injection is a web attack where the `Host` header is manipulated to influence server-side behavior. It can result in cache poisoning, web cache deception, or bypassing access control.

**Example**:
A vulnerable web server might use the `Host` header to construct links in emails:
```python
host = request.headers['Host']
reset_link = f"http://{host}/reset_password?token=abc123"
```
An attacker could modify the `Host` header:
```
evil.com
```
The reset link would be sent as:
```
http://evil.com/reset_password?token=abc123
```

**Potential Impacts**:
- Cache poisoning.
- Security policy bypass.
- Phishing attacks.

**Prevention**:
- Validate and whitelist `Host` headers.
- Use server-side configurations to reject malicious host headers.

