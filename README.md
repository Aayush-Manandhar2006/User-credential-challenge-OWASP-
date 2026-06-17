# User-credential-challenge-OWASP-
Exploiting and mitigating SQLi Injection vulnerability in OWASP Juice shop.

SQL Injection: Attack & Defense-in-Depth Mitigation — OWASP Juice Shop

A hands-on cybersecurity project demonstrating a UNION-based SQL Injection attack against OWASP Juice Shop (an intentionally vulnerable training application), followed by the design and implementation of a layered Defense-in-Depth mitigation in the application's backend.

Completed as part of a university cybersecurity coursework module. Shared here for educational and portfolio purposes.


⚠️ Disclaimer: All testing was performed exclusively against OWASP Juice Shop, an application built and maintained specifically for security training, running in an isolated Docker container. No real systems, third-party applications, or production data were targeted at any point.

Overview

Target application
OWASP Juice Shop (Dockerized)
Vulnerability: classSQL Injection — CWE-89 / OWASP A03:2021 Injection
Entry point: GET /rest/products/search?q=
Tools used: Burp Suite, SQLite, Node.js / TypeScript, Sequelize ORM
Outcome: Full database schema enumeration + extraction of all user credentials
Mitigation: Parameterized queries, whitelist input validation, string length limiting

The attack used a two-phase methodology — reconnaissance via sqlite_master to map the database schema, followed by data exfiltration to extract emails and passwords from the Users table. The mitigation applies three independent security layers directly to the search endpoint's backend code, so no single control is relied on exclusively.

📄 Full write-up: see "OWASP Juice Shop.pdf" for the complete methodology, payload breakdowns, request/response evidence, code walkthroughs, and evaluation of each mitigation's strengths and limitations.

💻 Code: the fixed backend implementation is in search.ts.

Target application: OWASP Juice Shop
Containerization: Docker
Interception/testing: Burp Suite
Backend: Node.js, TypeScript, Express
ORM / Database: SQLite


Disclaimer
This repository documents security research performed in a controlled, legal training environment (OWASP Juice Shop) for educational purposes as part of a university coursework assignment. The techniques described should only ever be applied to systems you own or have explicit authorization to test.
