-- Add migration script here
CREATE TABLE IF NOT EXISTS users
(
    id           SERIAL PRIMARY KEY NOT NULL,
    name         TEXT               NOT NULL,
    email        TEXT               NOT NULL,
    access_token TEXT               NOT NULL,
    avatar_url   TEXT,
    discord_id   TEXT
);
