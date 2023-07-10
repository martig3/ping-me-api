-- Add migration script here
CREATE TABLE IF NOT EXISTS users 
(
    id            INTEGER PRIMARY KEY NOT NULL,
    name          TEXT                NOT NULL,
    email         TEXT                NOT NULL,
    password_hash TEXT                NOT NULL,
    role          TEXT                NOT NULL,
    avatar_url    TEXT,
    discord_id    TEXT
);


CREATE TABLE IF NOT EXISTS user_invites
(
    id          INTEGER PRIMARY KEY NOT NULL,
    user_id     INTEGER                     ,
    email       TEXT                NOT NULL
);