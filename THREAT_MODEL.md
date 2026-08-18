# SecureVault — Threat Model

SecureVault is a **local, single-user desktop application**. This threat model
is scoped accordingly — it does not claim to defend against threats a desktop
application of this kind structurally cannot address (e.g. a fully compromised
host OS).

## Assets

1. User account credentials (passwords, MFA secrets, recovery codes)
2. Plaintext contents of files the user chooses to encrypt
3. The encryption keys used to protect those files (transient, in-memory only)
4. The audit log (evidence of what happened, when)
5. Session state (who is currently authenticated)

## Threats Considered

### T1 — Database file is stolen/copied (e.g. `securevault.db` exfiltrated)
- **Mitigation**: passwords are Argon2id-hashed (not reversible); MFA secrets
  and recovery codes are not encrypted at rest in this version (see Residual
  Risks) but recovery codes are themselves hashed; file encryption keys are
  never stored anywhere, only ever derived transiently in memory.
- **Residual risk**: an attacker with the DB file and unlimited compute can
  still attempt offline Argon2id cracking against weak passwords — hashing
  slows this down significantly but does not make weak passwords safe.

### T2 — Online brute-force login attempts
- **Mitigation**: 5-failure lockout for 15 minutes (`auth_core/user_service.py`).
- **Residual risk**: this is a local desktop app, not a networked service — an
  attacker with local access could restart the app or manipulate the DB
  directly to bypass the lockout counter. The lockout defends against a casual
  guessing attempt through the UI, not a determined local attacker with DB access.

### T3 — Wrong-password / tampered-ciphertext oracle
- **Mitigation**: `DecryptionError` deliberately gives the identical message
  for a wrong password and for tampered ciphertext/header, verified in tests.
- **Residual risk**: none identified for this specific concern within the
  local single-user scope.

### T4 — Audit log tampering (covering up malicious activity)
- **Mitigation**: SHA-256 hash chain; `verify_audit_log()` detects
  modification, deletion, or reordering of historical events.
- **Residual risk**: **stated plainly, not hidden** — an attacker with full
  write access to the SQLite file can rewrite the entire chain from any point
  forward and it will verify again internally. There is no external anchor
  (signed checkpoint, remote append-only store) in this version. This is
  tamper-*evident* against casual/partial modification, not tamper-*proof*
  against a fully capable local attacker.

### T5 — Disguised/malicious file uploaded for encryption or shared after decryption
- **Mitigation**: File Security Analyzer flags double extensions,
  extension/content mismatches, and executable signatures with explainable
  reasons; Quarantine removes flagged files from their expected name/location.
- **Residual risk**: this is a heuristic scanner, explicitly **not antivirus**
  — it does not detect malware by signature or behavior, only structural
  disguise patterns. A genuinely malicious PDF or a cleanly-named executable
  with no disguise characteristics will not be flagged.

### T6 — MFA bypass
- **Mitigation**: TOTP codes verified with `hmac.compare_digest`
  (constant-time); enrollment requires a live confirmation code before
  activation; recovery codes are single-use and Argon2id-hashed.
- **Residual risk**: TOTP secrets are stored in plaintext in the `mfa_devices`
  table (not separately encrypted at rest) — see Residual Risks below.

### T7 — "Secure delete" relied upon as guaranteed destruction
- **Mitigation**: the UI-facing `LIMITATIONS_NOTICE` states plainly that this
  does not guarantee destruction on SSDs, CoW filesystems, backups, or cloud
  sync.
- **Residual risk**: a user who doesn't read that notice may over-trust the
  feature. This is a documentation/UX risk, not a code defect — the honest
  claim is made available at the point of use.

## Attack Surfaces

- **Local file system access** — anyone with OS-level access to the machine
  running SecureVault can read `securevault.db` directly, bypassing the
  application entirely. This app assumes the OS/user-account boundary is the
  actual trust boundary, same as any local desktop credential manager.
- **The Tkinter UI itself** — no network listener, no remote attack surface.
- **Legacy Fernet decryption path** — intentionally kept for backward
  compatibility; it is only ever used to *decrypt* existing old files, never
  to encrypt new ones, so it does not expand the attack surface for new data.

## Mitigations Summary

Argon2id password hashing, AES-256-GCM authenticated file encryption with a
separate Argon2id KDF context, SQLite-enforced session state, brute-force
lockout, optional TOTP MFA with hashed recovery codes, a SHA-256 hash-chained
audit log, parameterized SQL throughout, and a heuristic file-risk scanner
with quarantine.

## Residual Risks (Explicit, Not Hidden)

1. **MFA secrets are stored in plaintext** in `mfa_devices.secret`. Argon2id
   hashing doesn't apply here (the secret must be recoverable to generate
   comparison codes, unlike a password). A future version should encrypt
   this at rest with a key derived from something the OS/user controls
   (e.g. OS keychain integration) rather than storing it as plain text in
   the SQLite file.
2. **The audit hash chain has no external anchor** (see T4).
3. **Encryption is not chunked/streamed** — very large files are loaded fully
   into memory; there's a practical (not cryptographic) size ceiling based on
   available RAM.
4. **Quarantine and secure-delete are local-only, best-effort mechanisms** —
   neither defends against a determined local attacker with root/admin access
   to the underlying OS or storage.
5. **No QR code rendering for MFA setup** in this build (offline environment
   constraint, not a security limitation per se, but a usability gap that
   could lead a user to mistype the manual secret).
