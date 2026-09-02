# Security policy

tvault stores authentication secrets, so please treat bugs here as sensitive.

## Reporting a vulnerability

Use GitHub's **[private vulnerability reporting](https://github.com/MahmoudElhalwany/tvault/security/advisories/new)**
rather than opening a public issue. Include what you can reproduce and, if you
have one, a proof of concept. Expect a first response within a week.

Please don't post working exploits in public issues or pull requests before a
fix is available.

## Scope

In scope, and taken seriously:

- Recovering vault contents without the master password.
- Weakening encryption or key derivation by editing the vault file.
- Any path that lets a web page, or an extension other than tvault's, obtain
  secrets from the native host.
- Secrets reaching disk, logs, process arguments, or the browser's storage.
- Autofill writing credentials into a page other than the one the user chose.

Out of scope — these follow from the threat model, not from bugs:

- **Malware running as your user.** It can read `~/.tvault/vault.json` and can
  talk to the unlock agent while it is unlocked. Every local password manager
  shares this limitation.
- **A forgotten master password.** There is deliberately no recovery path.
- **Physical access to an unlocked machine** with the agent unlocked.

## Design notes for reviewers

- Vault: AES-256-GCM. Key from scrypt, N=2^17, r=8, p=1, 32-byte output.
- The vault header, including the KDF parameters, is passed to GCM as
  additional authenticated data, so editing them breaks authentication rather
  than downgrading the KDF.
- The derived key is held only in the memory of the agent process
  (`tvault/agent.py`). Access control is filesystem-based: a 0600 socket inside
  a 0700 directory, the same approach as ssh-agent.
- The native host manifest pins `allowed_origins` to a single extension ID,
  derived from the public key in `extension/manifest.json`.
- The extension declares no host permissions and no content scripts. Its
  `list` request returns metadata only; secrets cross to the browser solely in
  response to an explicit click.

Cryptographic review is especially welcome. See `tests/test_tvault.py` for the
properties currently asserted.
