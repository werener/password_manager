# Password Manager

A small password-vault backend API. It provides user authentication and CRUD for stored credentials.

- Register/login users.
- Store credentials in a zero-knowledge setting.
- Protect credential endpoints with bearer access tokens.
- Support refresh-token rotation and logout.

## Passman

### Subcommands
server    Set backend server URL
config    Show current configuration and session status
register  Register a new account
login     Login to an account
logout    Logout from current account
add       Add a credential
list      List credentials
get       Get a credential by id
edit      Edit a credential by id
delete    Delete a credential by id
help      Print this message or the help of the given subcommand(s)

### Build from source
Requires a Rust toolchain.

```bash
cargo build --release -p passman
```
You can also install it into Cargo's bin directory:

```bash
cargo install --path crates/passman
```

## API

### Run with Docker Compose
Configure `.env`, using the template from `.env.example`.
Then run:

```bash
docker compose up --build
```

First build may take a while, since a backend binary is being built from source.

### Health
- `GET /health` -> `200` when all dependencies are healthy, `503` when degraded
  - Response: `{ "status": "ok"|"degraded", "db": "up"|"down", "redis": "up"|"down" }`

### Auth
- `POST /auth/register`
  - Body: `{ "email": string, "auth_verifier": string, "kdf_salt": string }`
  - Returns: `201` with `{ "user_id", "email" }`

- `POST /auth/prelogin`
  - Body: `{ "email": string }`
  - Returns: `200` with `{ "kdf_salt": string }`

- `POST /auth/login`
  - Body: `{ "email": string, "auth_verifier": string }`
  - Returns: `200` with access/refresh tokens, token type, expirations, and `kdf_salt`

- `POST /auth/refresh`
  - Body: `{ "refresh_token": string }`
  - Returns: `200` with a new token pair; old refresh token is invalidated

- `POST /auth/logout`
  - Body: `{ "refresh_token": string }`
  - Returns: `204`

### Credentials
All credential endpoints require
`Authorization: Bearer <access_token>`

- `POST /credentials`
  - Headers: `Idempotency-Key: <unique-key>`
  - Body:
    ```json
    {
      "name": "string",
      "username": "string|null (optional)",
      "url": "string|null (optional)",
      "notes": "string|null (optional)",
      "password_ciphertext": "string",
      "password_nonce": "string"
    }
    ```
  - Returns: `201` with created credential

- `GET /credentials`
  - Returns: `200` with credential metadata list

- `GET /credentials/:id`
  - Returns: `200` with credential including `password_ciphertext` and `password_nonce`

- `PUT /credentials/:id`
  - Body: any subset of credential fields
  - For `username`, `url`, and `notes`, sending `null` clears the field; omitting the field leaves it unchanged
  - If updating the secret, include both `password_ciphertext` and `password_nonce`
  - Returns: `200` with updated credential

- `DELETE /credentials/:id`
  - Returns: `204`


