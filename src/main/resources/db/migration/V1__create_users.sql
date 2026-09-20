create table users (
    id            uuid primary key,
    email         varchar(254) not null,
    password_hash varchar(100) not null,
    role          varchar(20)  not null,
    created_at    timestamp with time zone not null,
    constraint uk_users_email unique (email)
);
