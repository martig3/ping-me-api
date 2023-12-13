-- Add migration script here
CREATE TABLE IF NOT EXISTS users 
(
    id            INTEGER PRIMARY KEY NOT NULL,
    name          TEXT                NOT NULL,
    email         TEXT                NOT NULL,
    pw_hash       TEXT                NOT NULL,
    role          TEXT                NOT NULL,
    access_token  TEXT                NOT NULL,
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

-- Create `groups` table.
create table if not exists groups (
    id integer primary key autoincrement,
    name text not null unique
);

-- Create `permissions` table.
create table if not exists permissions (
    id integer primary key autoincrement,
    name text not null unique
);

-- # Join tables.

-- Create `users_groups` table for many-to-many relationships between users and groups.
create table if not exists users_groups (
    user_id integer references users(id),
    group_id integer references groups(id),
    primary key (user_id, group_id)
);

-- Create `groups_permissions` table for many-to-many relationships between groups and permissions.
create table if not exists groups_permissions (
    group_id integer references groups(id),
    permission_id integer references permissions(id),
    primary key (group_id, permission_id)
);