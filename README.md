# Social Chat App

Social media + private messaging application.

## Architecture

- Flutter mobile application
- Cloudflare Workers API
- Cloudflare D1 database
- Private messages designed around end-to-end encryption

The server/database should store encrypted message ciphertext, not plaintext message content.

## Backend

The Cloudflare Worker is in `backend/`.
