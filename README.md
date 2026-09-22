# Virexa Markets V6 — Client Portal + Admin Demo

This is a development build for the Virexa Markets project.

## Run locally
1. Install Node.js 18+.
2. Extract this folder.
3. Run: npm install
4. Copy `.env.example` to `.env` and set a strong SESSION_SECRET.
5. Run: npm start
6. Open http://localhost:3000

## Default admin (development only)
Email: admin@virexa.local
Password: ChangeMe-Admin-123!

Change these before any deployment.

## Important
This build intentionally keeps live trading, deposits, withdrawals and client-money custody disabled.
The demo uses a JSON data file for development. Render's default filesystem is ephemeral, so this is NOT a production database.
For production, use managed PostgreSQL/Redis or another appropriate persistent architecture, MFA, secure cookies, email verification/password recovery, CSRF protections where applicable, secrets management, monitoring, backups, penetration testing, and independent legal/regulatory review.
