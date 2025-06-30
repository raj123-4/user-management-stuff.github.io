# User Management System

This is a minimal user management API built with Node.js using only built-in modules. It supports:

- User registration and login with password hashing.
- JWT-like token generation for session management.
- Admin endpoints to list users, grant or revoke access, and view user logs.
- Access status tracking (Active, Expired, Revoked) based on expiration time or manual revocation.

## Running

```bash
node server.js
```

The server listens on port `3000` and stores data in `users.json` in the project directory.

## API Endpoints

- `POST /register` – `{ name, email, password }`
- `POST /login` – `{ email, password }`
- `GET /me` – requires `Authorization` header with token
- `GET /admin/users` – admin only
- `POST /admin/grant/:id` – admin only, body `{ days }`
- `POST /admin/revoke/:id` – admin only
- `GET /admin/logs/:id` – admin only

Tokens are returned on login and must be sent in the `Authorization` header.

## PDF Upload Service

A simple Flask app `pdf_extract.py` accepts PDF uploads and returns the text of each page as JSON. Install dependencies with `pip install flask pdfplumber` and run:

```bash
python pdf_extract.py
```

Send a `POST /upload` request with form-data key `pdf` to receive a list of pages and their text.

## PDF QA Helper

Use `pdf_qa.py` to search a PDF for the answer to a question:

```bash
python pdf_qa.py document.pdf "What is the meaning of life?"
```

You will be prompted for your question, and if Pillow is available the matching page image will open in a viewer.
The script prints a snippet from the page with the most keyword matches and shows its page number.

