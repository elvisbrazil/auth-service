# auth-service

A small authentication service built with Spring Boot 3 and Spring Security. Users register with email and password, log in to get a short-lived RS256 access token plus an opaque refresh token, and use the access token against protected endpoints. Refresh tokens are rotated on every use, and presenting an already used token revokes the whole session it belongs to.

## Running

Requirements: Java 21 and Docker.

```sh
./mvnw verify                 # build, lint (Spotless + Checkstyle) and tests (H2 in PostgreSQL mode)
docker compose up -d          # PostgreSQL on localhost:5432
./mvnw spring-boot:run
```

Without a configured key pair the service generates an RSA key on startup, so tokens stop working after a restart. To use a fixed key:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem
openssl rsa -in private.pem -pubout -out public.pem
AUTH_JWT_PRIVATEKEY=file:private.pem AUTH_JWT_PUBLICKEY=file:public.pem ./mvnw spring-boot:run
```

Set `BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD` to create an admin account on startup.

## Endpoints

| Method | Path             | Auth          |
|--------|------------------|---------------|
| POST   | `/auth/register` | none          |
| POST   | `/auth/login`    | none          |
| POST   | `/auth/refresh`  | refresh token |
| POST   | `/auth/logout`   | refresh token |
| GET    | `/me`            | access token  |
| GET    | `/admin/users`   | ADMIN role    |

Errors are returned as `application/problem+json`.

## Design notes

- Access tokens are JWTs signed with RS256 through Spring Security's `JwtEncoder`/`JwtDecoder` (Nimbus). They carry the user id as `sub` and the role, and live for 15 minutes.
- Refresh tokens are 256-bit random strings. Only their SHA-256 hash is stored, so a database leak does not hand out usable sessions. A plain hash is enough here because the input is random, unlike a password.
- Each login starts a token family. Refreshing marks the current token as used and issues the next one in the same family. If a used token shows up again, someone is holding a copy, so every token in the family is revoked and both parties have to log in again.
- Logout revokes the family of the given refresh token. Access tokens already issued stay valid until they expire; that is the usual trade-off of short-lived stateless tokens.
- Failed logins are counted per email in memory: after 5 failures the email is locked for 15 minutes and login returns 429 with `Retry-After`. This is per instance and is lost on restart; a multi-instance deployment would move it to Redis or the database.
- Unknown emails still go through a BCrypt comparison so response times do not reveal which emails are registered.
- Password policy: 10 to 72 characters (BCrypt ignores anything past 72 bytes), at least one letter and one digit, not equal to the email.
