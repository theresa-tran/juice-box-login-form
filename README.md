# Juice Box — Secure Login Form (HW 2B, Part 2)

A minimal login form inspired by OWASP Juice Shop's login page, built to
demonstrate secure front-end **and** back-end practices rather than relying
on client-side checks alone.

## What this is

- `public/index.html` — the login form (email + password) with client-side
  JavaScript validation (checks the email contains `@` and the password is
  at least 8 characters before the request is even sent).
- `server.py` — a small Flask backend that re-validates everything
  server-side, stores passwords as **bcrypt hashes** (never plaintext),
  uses **parameterized SQL queries** (no string concatenation → no SQL
  injection), returns a generic error message so it never reveals whether
  an email exists, and rate-limits repeated attempts from the same IP.
- `vulnerable_version_for_testing.py` — an intentionally insecure twin of
  `server.py` (string-concatenated SQL, plaintext passwords). It exists
  **only** so the SQL injection attack in Part 3 of the assignment could be
  run and documented against a real server. It is not used by the form in
  normal operation.

## Why client-side validation alone is not security

The JavaScript checks in `index.html` only improve user experience (instant
feedback, fewer wasted round-trips). They can be bypassed trivially — by
disabling JavaScript, using `curl`/Postman, or editing the DOM — so
`server.py` repeats every check independently and is the actual security
boundary.

## How to run it

1. Install dependencies:
   ```bash
   pip install flask bcrypt
   ```
2. Start the secure server:
   ```bash
   python3 server.py
   ```
3. Open **http://127.0.0.1:5000** in a browser.
4. Log in with the seeded demo account:
   - Email: `demo@juicebox.local`
   - Password: `Password123`

A SQLite file (`users_secure.db`) is created automatically on first run.

### Running the vulnerable version (for the Part 3 exploit demo only)

```bash
python3 vulnerable_version_for_testing.py
```
Runs on port 5001 with its own database (`users_vulnerable.db`). See the
submission write-up (Part 3) for the exact exploit steps and output.

## Security measures implemented

| Risk                         | Mitigation in `server.py`                                   |
|------------------------------|---------------------------------------------------------------|
| SQL Injection                 | Parameterized queries (`?` placeholders), never string-built SQL |
| Plaintext password storage    | `bcrypt.hashpw` / `bcrypt.checkpw`                           |
| Client-side-only validation   | Server re-validates email format and password length         |
| User enumeration               | Identical generic error for "no such user" and "wrong password" |
| Reflected XSS                  | Server never echoes raw input back into HTML; front-end uses `textContent`, never `innerHTML` |
| Brute force / credential stuffing | Simple in-memory per-IP rate limiter (5 attempts / 60s)   |
