# Juice Box â€” Secure Login Form

A login form inspired by OWASP Juice Shop's login page, built as a secure
user registration/login flow: client-side validation for a responsive UI,
backed by independent server-side validation and secure data handling.

## What this is

- `public/index.html` â€” the login form (email + password fields) with
  client-side JavaScript validation: blocks empty submissions, checks the
  email contains `@`, and requires a password of at least 8 characters
  before a request is ever sent.
- `server.py` â€” a small Flask backend that is the actual security
  boundary. It:
  - Re-validates email format and password length **server-side**,
    independent of the client.
  - Stores passwords only as **bcrypt hashes**, never plaintext.
  - Uses **parameterized SQL queries** (`?` placeholders) â€” no string
    concatenation, so user input can never alter the query's structure.
  - Returns the **same generic error message** whether the email doesn't
    exist or the password is wrong, so accounts can't be enumerated.
  - **Rate-limits** repeated login attempts per IP address.

## Why both client-side and server-side validation

The JavaScript checks in `index.html` only improve the user experience
(instant feedback, fewer wasted round-trips) â€” they can be bypassed
trivially, e.g. by disabling JavaScript or calling the API directly with a
tool like `curl` or Postman. `server.py` repeats every check independently
and is the real line of defense.

## How to run it

1. Install dependencies:
   ```bash
   pip install flask bcrypt
   ```
2. Start the server:
   ```bash
   python3 server.py
   ```
3. Open **http://127.0.0.1:5000** in a browser.
4. Log in with the seeded demo account:
   - Email: `demo@juicebox.local`
   - Password: `Password123`

A SQLite database file (`users_secure.db`) is created automatically on
first run and is excluded from version control via `.gitignore`.

## Security measures implemented

| Risk                             | Mitigation in `server.py`                                          |
|-----------------------------------|----------------------------------------------------------------------|
| SQL Injection                     | Parameterized queries (`?` placeholders), never string-built SQL   |
| Plaintext password storage        | `bcrypt.hashpw` / `bcrypt.checkpw`                                  |
| Client-side-only validation       | Server re-validates email format and password length independently |
| User enumeration                  | Identical generic error for "no such user" and "wrong password"    |
| Reflected XSS                     | Server never echoes raw input back into HTML; front-end uses `textContent`, never `innerHTML` |
| Brute force / credential stuffing | In-memory per-IP rate limiter (5 attempts / 60s)                    |