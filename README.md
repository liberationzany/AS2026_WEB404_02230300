# WEB404 Secure Coding Practices

This repository contains the practical assignments for the WEB404 Secure Coding Practices module. Each assignment is a small, self-contained web application implemented twice, once deliberately vulnerable, once hardened so the two can be compared directly against the same attack. Every assignment folder includes the application source (`app.py`), a full write-up (`README.md`) covering methodology, test results, and mitigation, and supporting screenshots/transcripts under `assets/`.

## Assignments

| # | Folder | Topic | Port |
| --- | --- | --- | --- |
| 5 | [`assignments/assignment1`](assignments/assignment1) | SQL injection | 8080 |
| 3 | [`assignments/assignment2`](assignments/assignment2) | File upload security | 8081 |
| 2 | [`assignments/assignment3`](assignments/assignment3) | Command injection | 8082 |
| 6 | [`assignments/assignment4`](assignments/assignment4) | CSRF | 8083 |
| 7 | [`assignments/assignment5`](assignments/assignment5) | JWT authentication | 8084 |

## Running an assignment

Each assignment is a standalone Python script with no external dependencies:

```bash
cd assignments/assignment1
python app.py
```

Then open the printed `http://127.0.0.1:<port>` address in a browser. Every app binds only to `127.0.0.1` and is intended for local, authorised testing only — see each assignment's `README.md` for its ethical scope, full test walkthrough, and remediation details.
