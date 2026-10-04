create table refresh_tokens (
    id          uuid primary key,
    user_id     uuid        not null references users (id) on delete cascade,
    family_id   uuid        not null,
    token_hash  varchar(64) not null,
    created_at  timestamp with time zone not null,
    expires_at  timestamp with time zone not null,
    used_at     timestamp with time zone,
    revoked_at  timestamp with time zone,
    constraint uk_refresh_tokens_hash unique (token_hash)
);

create index ix_refresh_tokens_family on refresh_tokens (family_id);
