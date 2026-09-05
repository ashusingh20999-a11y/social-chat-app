-- One-time cleanup requested for the new auth system.
-- Run once in Cloudflare D1 if you want to clear existing auth records:
DELETE FROM sessions;
DELETE FROM auth_users;
