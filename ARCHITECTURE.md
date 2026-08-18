# SecureVault — Architecture

## Layering

```
UI (Tkinter: auth.py, dashboard.py, encrypt.py, decrypt.py)
        |
Service layer (auth_core/, services/)
        |
Core / security-critical logic (core/, audit/)
        |
Database (database/, SQLite)
```

Rule enforced throughout: **Tkinter callbacks call functions in the layers
below; cryptography, password hashing, and SQL never live inside a GUI
callback.** Every module under `core/`, `auth_core/`, `audit/`, `services/`,
and `database/` imports zero Tkinter code, so all of it is testable headlessly
— which is how ~140 tests run in this project without a display.

## Module Map

| Module | Responsibility |
|---|---|
| `auth_core/password.py` | Argon2id hashing for the **login password verifier** |
| `auth_core/user_service.py` | register/authenticate, brute-force lockout policy |
| `auth_core/session.py` | SQLite-backed session state + enforcement |
| `auth_core/migration.py` | one-time plaintext `users.json` → SQLite migration |
| `auth_core/mfa.py` | RFC 6238 TOTP primitives |
| `auth_core/mfa_service.py` | MFA enrollment/login/disable + recovery codes |
| `core/crypto.py` | AES-256-GCM wrapper (encrypt/decrypt, nonce generation) |
| `core/kdf.py` | Argon2id for **file encryption keys** (separate context from `auth_core/password.py`) |
| `core/file_format.py` | versioned `SVLT` container: pack/unpack, integrity |
| `core/scanner.py` | deterministic file risk analysis |
| `core/secure_delete.py` | overwrite-then-unlink workflow |
| `core/security_center.py` | computed security score + posture + recommendations |
| `audit/logger.py` | `log_event`/`list_events`/`search_events`, hash chaining |
| `audit/verifier.py` | walks the chain, reports VERIFIED or the first broken event |
| `services/quarantine_service.py` | quarantine/list/inspect/restore/delete |
| `services/report_service.py` | aggregates audit data into JSON/CSV/PDF reports |
| `database/db.py` | connection management, schema, transactions |
| `database/user_repository.py` | parameterized queries over `users` |
| `crypto_utils.py` | the stable public API `encrypt.py`/`decrypt.py` actually call |

## Why `crypto_utils.py` Still Exists

`encrypt.py` and `decrypt.py` (the Tkinter pages) call
`encrypt_file_data()`/`decrypt_file_data()` in `crypto_utils.py` — the same
function names and signatures as the original project. Internally, that
module now delegates to `core/file_format.py` for new encryption and
transparently falls back to the legacy Fernet path for old files. This kept
the UI pages themselves nearly untouched during the Phase 3 cryptography
upgrade, rather than forcing a simultaneous UI rewrite alongside a crypto
rewrite.

## Data Flow: Encrypting a File

```
EncryptPage (Tkinter)
  -> crypto_utils.encrypt_file_data(data, password, filename)
       -> core.file_format.encrypt_file()
            -> core.kdf.derive_key()      (Argon2id, fresh salt)
            -> core.crypto.encrypt()      (AES-256-GCM, fresh nonce)
       -> returns SVLT container bytes
  -> written to disk
  -> audit.logger.log_event(FILE_ENCRYPTED, ...)
```

## Data Flow: A Login

```
LoginApp.login() (Tkinter)
  -> auth_core.user_service.authenticate_user(username, password)
       -> database.user_repository.get_user_by_username()
       -> auth_core.password.verify_password()  (Argon2id verify)
       -> lockout check / failed-attempt tracking
  -> on success: auth_core.session.create_session()
  -> audit.logger.log_event(LOGIN_SUCCESS or LOGIN_FAILURE/ACCOUNT_LOCKED)
```

## Database Schema (SQLite)

- `users` — id, username, password_hash, timestamps, failed_attempts,
  locked_until, last_login, account_status, mfa_enabled
- `sessions` — id (uuid), username, created_at, last_activity, state, ended_at
- `mfa_devices` — username (PK), secret, confirmed, created_at
- `recovery_codes` — id, username, code_hash, used, created_at
- `quarantine_items` — quarantine_id (PK), username, original_filename,
  original_path, quarantined_path, sha256, risk_level, reasons (JSON), state,
  created_at, resolved_at
- `audit_events` — id, timestamp, event_type, username, result, object_id,
  metadata (JSON), prev_hash, event_hash
- `migration_state` — key/value flags (e.g. legacy migration completion)

## Why Some Data Stays in JSON

`profiles.json` (profile photo path), `stats.json` (display counters),
`history.json` (legacy activity display list), `settings.json` (UI
preferences), `theme.json` (dark/light) hold no credentials and no
security-relevant state — they were deliberately left as JSON rather than
migrated, since SQLite migration was reserved for genuinely
security/audit-relevant data (see `SECURITY.md`). `users.json` is the one
exception: it's still on disk, but only as an untouched backup — it is never
read for authentication after the one-time migration completes.

## Known Architectural Gaps

- The main Dashboard's per-user counters (`stats.json`-based) were not fully
  replaced with SQLite/audit-sourced equivalents in this release; the
  Dashboard's status banner does now show the real, computed Security Score,
  but the encrypted/decrypted file counters still read `stats.json`. Both
  data sources are internally consistent (stats.json is still updated on
  every real encrypt/decrypt), so this is a duplication-of-source-of-truth
  issue, not a correctness bug — but it should be unified in a future pass.
- Encryption/decryption load whole files into memory; there is no chunked
  streaming path for very large files (see `SECURITY.md` limitations).
