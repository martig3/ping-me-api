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

CREATE TABLE IF NOT EXISTS metadata
(
    id             INTEGER PRIMARY KEY NOT NULL,
    created_by     INTEGER                     ,
    bucket         TEXT                NOT NULL,
    file_name      TEXT                NOT NULL,
    full_path      TEXT                NOT NULL
);

CREATE INDEX metadata_bucket_idx ON metadata(bucket);
CREATE INDEX metadata_file_name_idx ON metadata(file_name);