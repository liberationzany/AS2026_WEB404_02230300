# Practical Report: SQL Injection Vulnerability Assessment

**Course:** WEB404 — Web Application Development  
**Practical:** 5 — Vulnerable web application and SQL injection  
**Student:** Sonam Tenzin

## 1. Objective

The purpose of this practical was to set up a deliberately vulnerable web application, identify SQL injection weaknesses, demonstrate their impact in an authorised local environment, and compare the vulnerable implementation with a secure implementation using parameterized SQL queries.

## 2. Ethical scope

All testing was carried out against a self-created application on `127.0.0.1` (localhost). The application uses fictional accounts and a disposable SQLite database. No external system, real account, or network service was tested. SQL injection testing must only be performed with explicit authorisation.

## 3. Environment and setup

| Component | Details |
| --- | --- |
| Operating system | Windows |
| Language | Python 3.14 |
| Web server | Python `ThreadingHTTPServer` |
| Database | SQLite |
| Application address | `http://127.0.0.1:8080` |
| Application file | `app.py` |

The lab was started with the following command:

```powershell
python app.py
```

The server was intentionally restricted to localhost. On every launch, it recreated `training_lab.db` containing three fictional users: `alice`, `bob`, and `instructor`.

## 4. Vulnerability description

SQL injection occurs when an application combines untrusted user input directly into an SQL statement. The vulnerable login page used string formatting in the following pattern:

```sql
SELECT id, username, role FROM users
WHERE username = '<username input>' AND password = '<password input>'
```

Because the input was inserted directly into the query, quotation marks, SQL operators, and comments supplied by a user could alter the intended query logic.

## 5. Test results

### Test 1: Normal authentication baseline

| Item | Observation |
| --- | --- |
| Page | Vulnerable login |
| Input | Username: `alice`; Password: `orchid-47` |
| Result | Login succeeded as `alice` with the `student` role. |
| Purpose | Confirmed that the application and database were functioning before injection testing. |

![Figure 1: Successful baseline login](assets/test1.png)

### Test 2: Authentication bypass using SQL comments

| Item | Observation |
| --- | --- |
| Page | Vulnerable login |
| Input | Username: `alice' -- `; Password: any value |
| Result | The application logged in as `alice` without validating the supplied password. |
| Vulnerability type | Tautology/comment-based authentication bypass |

The resulting SQL was equivalent to:

```sql
SELECT id, username, role FROM users
WHERE username = 'alice' -- ' AND password = 'any value'
```

The SQL comment marker caused the password condition to be ignored. This demonstrates that direct query construction can allow an attacker to bypass authentication.

![Figure 2a: Injected login credentials](assets/test2password.png)

![Figure 2b: Authentication bypass result](assets/test2loggedin.png)

### Test 3: Error-based SQL injection discovery

| Item | Observation |
| --- | --- |
| Page | Vulnerable search |
| Input | A single quotation mark: `'` |
| Result | SQLite returned a syntax error. |
| Vulnerability type | Error-based SQL injection |

The error occurred because the quotation mark terminated the string value used by the query. Detailed database errors help attackers understand the database syntax and should not be shown to end users in a production application.

![Figure 3: Error-based SQL injection result](assets/test3.png)

### Test 4: UNION-based data extraction

| Item | Observation |
| --- | --- |
| Page | Vulnerable search |
| Input | `' UNION SELECT id, username, password FROM users -- ` |
| Result | The search page displayed records from the `users` table, including the demonstration password values. |
| Vulnerability type | UNION-based SQL injection |

The original search query selected three columns. The injected `UNION SELECT` also returned three compatible columns, allowing data from the database to be combined with the normal search results. The third selected field (`password`) appeared in the page column normally used for roles.

![Figure 4: UNION-based extraction result](assets/test4.png)

### Test 5: Boolean-blind SQL injection

| Item | Observation |
| --- | --- |
| Page | Blind check |
| Baseline input | A nonexistent username, for example `nobody` |
| Baseline result | `No matching account.` |
| Injection input | `' OR '1'='1' -- ` |
| Injection result | `Account exists.` |
| Vulnerability type | Boolean-blind SQL injection |

Unlike the search page, this endpoint does not show records, query text, or database errors. It only returns one of two messages. The injection input makes the query condition true and changes the response from “No matching account” to “Account exists.” This demonstrates how an attacker can infer information one true/false condition at a time even when a web application hides detailed errors and results.

![Figure 5a: Baseline blind check response (nonexistent user)](assets/test5_nobody.png)

![Figure 5b: Boolean-blind SQL injection response showing "Account exists."](assets/test5.png)

## 6. Security impact

The findings show that SQL injection can have serious consequences:

- Authentication may be bypassed, allowing unauthorised access to user accounts.
- Sensitive records can be read from database tables.
- Error messages can reveal useful information about the database structure.
- In a real system with excessive database privileges, an injection flaw could potentially allow modification or deletion of data.

Although this lab uses fictional data, storing or exposing plain-text passwords would be especially harmful in a real application.

## 7. Mitigation and verification

The application included a **Safe search** page as a comparison. It used a parameterized query instead of placing the supplied value inside SQL text:

```python
query = "SELECT id, username, role FROM users WHERE username LIKE ?"
rows = connection.execute(query, (f"%{term}%",)).fetchall()
```

When the quote and UNION inputs from Tests 3 and 4 were submitted to this page, they were treated as ordinary search terms. No SQL error occurred and no additional records were returned. This verifies that parameterized queries prevent the input from changing the SQL statement’s structure.

**Replication steps**

1. Open `http://127.0.0.1:8080/safe-search`.
2. Submit the single quote and UNION inputs used in Tests 3 and 4, one at a time.
3. Verify that neither input produces a database error or extracts records.
4. Record the query and parameters shown by the page.

Recommended defenses are:

- Use parameterized queries (prepared statements) for every database operation.
- Never construct SQL by concatenating or formatting user input.
- Hash passwords with a dedicated password-hashing algorithm such as Argon2 or bcrypt; never store plain-text passwords.
- Display generic error messages to users and store technical error details only in protected server logs.
- Use a database account with only the permissions required by the application.
- Validate input as an additional control, while recognising that validation does not replace parameterized queries.

## 8. Conclusion

The practical successfully demonstrated four SQL injection outcomes in a controlled local environment: authentication bypass, error-based discovery, UNION-based data extraction, and Boolean-blind inference. The vulnerable pages failed because they inserted user input directly into SQL statements. The parameterized implementation prevented the same payloads from changing the query logic. Therefore, prepared statements and secure password handling are essential controls for web applications that use databases.

## Appendix: Running and cleanup

Start the lab with `python app.py`, then browse to `http://127.0.0.1:8080`. Stop the server with `Ctrl+C`. The generated `training_lab.db` is disposable and is recreated whenever the application starts.
