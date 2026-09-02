# tvault

A local, encrypted vault for TOTP codes and passwords — a terminal app and a
Chrome extension sharing one file on your disk. No account, no sync, no
server. Nothing ever leaves the machine.

[![tests](https://github.com/MahmoudElhalwany/tvault/actions/workflows/tests.yml/badge.svg)](https://github.com/MahmoudElhalwany/tvault/actions/workflows/tests.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

```
$ tvault code github
GitHub (me@example.com)
  418 902  ████████░░░░ 19s left
copied to clipboard (clears in 30s)
```

## How it fits together

```
  terminal                      Chrome
  ┌──────────┐                  ┌──────────────┐
  │  tvault  │                  │  extension   │
  └────┬─────┘                  └──────┬───────┘
       │                               │ native messaging
       │                        ┌──────┴───────┐
       │                        │ tvault-host  │
       │                        └──────┬───────┘
       ├───────────────┬───────────────┤
       ▼               ▼               ▼
  ~/.tvault/vault.json         tvault agent (RAM only)
  AES-256-GCM                  holds the derived key, 15 min idle
```

The extension has no storage of its own and no network access. It asks the
native host over Chrome's native-messaging channel — no localhost port, nothing
listening. The host asks the agent for the key, and that key exists only in the
memory of a detached process.

## Requirements

Python 3.10 or newer, and a Chromium-family browser (Chrome, Brave, Edge,
Chromium, Vivaldi, Arc) if you want the extension. macOS and Linux.

## Install

```sh
git clone https://github.com/MahmoudElhalwany/tvault.git
cd tvault
make bootstrap        # venv, dependencies, native messaging host
make init             # choose your master password
```

Put the CLI on your `PATH`:

```sh
echo 'export PATH="$HOME/.tvault/bin:$PATH"' >> ~/.zshrc && exec zsh
```

Then load the extension: open `chrome://extensions`, turn on **Developer
mode**, click **Load unpacked**, and choose this repo's `extension/` folder.
Confirm the ID Chrome shows matches `tvault extension-id` — the native host
accepts connections from that ID and no other.

> The repo ships a public key in `extension/manifest.json` so the ID is stable
> and `make install` works out of the box. It is only an identifier; the
> private half is generated locally and never committed. To mint your own
> identity, run `python scripts/genkey.py --force`, then `tvault install-chrome`
> and reload the extension.

## Adding accounts

When a site shows a 2FA QR code there is almost always a "can't scan it?" link
revealing the secret or an `otpauth://` URI.

```sh
tvault add --uri 'otpauth://totp/GitHub:me@example.com?secret=JBSW...&issuer=GitHub' --url github.com
tvault add GitHub -s JBSWY3DPEHPK3PXP -u me@example.com --url github.com
```

Or work through it interactively. `tvault add -i` asks what kind of entry you
want and then only asks for the fields that kind needs — a code-only entry is
never dragged through username and password prompts:

```
$ tvault add --otp
Secret or otpauth:// URI: otpauth://totp/GitHub:me@example.com?secret=JBSW...
  → GitHub (me@example.com)
Website for browser autofill (optional): github.com
✓ added GitHub (TOTP)
```

Pasting an `otpauth://` URI fills in the name, issuer and account for you.
`--otp`, `--login` and `--both` skip the menu when you already know which you
want.

### Moving in from Google Authenticator

Google Authenticator's **Export accounts** QR encodes an `otpauth-migration://`
payload holding every selected account at once. tvault decodes it locally, so
the seeds never leave your machine.

> **Never paste that payload into an online QR decoder.** One export QR
> contains every seed you selected. Decode it offline or not at all.

1. On your phone: Google Authenticator → **⋮** → **Transfer accounts** →
   **Export accounts**, authenticate, pick the accounts, then **Next**. It
   shows a QR code — several, in batches, if you have many accounts.
2. Screenshot it and get the image onto your computer (AirDrop is easiest).
3. Import it:

```sh
tvault import --qr ~/Downloads/export.png
```

```
decoded 1 QR code(s) from 1 image(s) using Apple Vision
✓ imported 3 entries
  · GitHub (me@example.com) (TOTP)
  · Okta (work@corp.com) (TOTP)
  · AWS (root) (TOTP)
```

4. Repeat for each QR if the export was split into batches — pass several
   images at once with `tvault import --qr a.png b.png`.
5. **Check a few codes against the app before you delete anything**, then
   remove the screenshots — they are as sensitive as the vault itself:

```sh
tvault watch                       # compare side by side with your phone
rm ~/Downloads/export.png
```

Keep Google Authenticator installed until you're confident in the migration.

### Adding a single account from a QR

If the QR is on a web page, the quickest route is the extension's **Scan QR**
button — see [In the browser](#in-the-browser). From the terminal, press
`Cmd-Ctrl-Shift-4` to copy a screen selection to the clipboard, then:

```sh
tvault import --qr                 # no argument: read the clipboard
```

On macOS, `make bootstrap` installs the decoder (Apple's Vision framework via
PyObjC — no Homebrew needed). On Linux, `sudo apt install zbar-tools` or
`pip install opencv-python-headless`; `make qr` reports which backend is
active. Without one, tvault says so rather than failing quietly, and you can
still paste a decoded URI with `tvault import -`.

Passwords live on the same entry, so one record holds the login *and* its 2FA:

```sh
tvault add AWS -u root@example.com -g 32 --url console.aws.amazon.com
tvault edit github -g              # rotate to a freshly generated password
```

## Everyday use

| Command | What it does |
|---|---|
| `tvault code <name>` | print the code and copy it (auto-clears after 30s) |
| `tvault code <name> -q` | print only the code, for scripts |
| `tvault watch` | live view of every code with countdown bars |
| `tvault pass <name>` | copy a password to the clipboard |
| `tvault ls` | list entries; `--host github.com` filters by site |
| `tvault show <name>` | one entry's details; `--secret` reveals the seed |
| `tvault edit <name>` | change any field |
| `tvault gen -l 32` | generate a password (`-w` for a passphrase) |
| `tvault lock` / `unlock` | drop or cache the key |
| `tvault status` | vault path, agent state, time until lock |
| `tvault passwd` | change the master password (re-encrypts everything) |
| `tvault import --qr <img>` | import from a QR image, or the clipboard |
| `tvault export` | plaintext dump — asks for confirmation first |

Names match loosely, so `tvault code git` finds `GitHub`. An ambiguous query
says so rather than guessing.

## In the browser

Click the toolbar icon, or press `Alt+Shift+V`. Entries for the current site
sort to the top. Click a code to copy it; **Fill** writes the username and
password into the page; **Fill + code** also enters the current OTP —
including into split six-box 2FA inputs and into login forms inside iframes.

Fields are set through the native `value` setter followed by real `input` and
`change` events, so React and Vue forms register the value instead of silently
reverting it.

**Scan QR** adds an account without leaving the page. When a site shows you a
2FA setup QR, click it: the extension screenshots the tab, the native host
decodes the QR locally, and you get a confirmation listing what it found
before anything is written.

```
Found on this page
  GitHub
  me@example.com
1 account on this page, will be linked to github.com.
   [ Add to vault ]  [ Cancel ]
```

The preview carries no secret into the browser — only the issuer and account
name. The seed goes straight from the decoder into the vault, and the entry is
linked to the current site so it surfaces there next time. Rescanning the same
code is a no-op rather than a duplicate.

## Security model

- **At rest**: AES-256-GCM. The key comes from scrypt with N=2¹⁷, r=8, p=1
  (~0.3 s per attempt, which is what makes brute force expensive). The vault
  header — including the KDF parameters — is bound in as additional
  authenticated data, so editing the file to weaken the KDF breaks decryption
  instead of downgrading it. The file is `0600`, written atomically.
- **While unlocked**: the derived key sits in a detached agent process and is
  never written to disk. Its socket is `0600` inside a `0700` directory, so
  only your uid can reach it. It forgets the key after 15 minutes idle
  (`--ttl` to change) and on `tvault lock`.
- **Browser boundary**: the host manifest allows exactly one extension ID. The
  extension requests `nativeMessaging`, `activeTab`, `scripting` and
  `clipboardWrite` — no host permissions, no content scripts, so it cannot read
  pages until you click it. `list` returns metadata only; a password or seed
  crosses to the browser solely on an explicit click and is never stored there.
  QR scanning screenshots the tab only on a click, decodes it in the native
  host, and the preview you confirm contains no secret.
- **Clipboard**: copies auto-clear after 30 seconds, and only if the clipboard
  still holds the value that was copied.

What this does *not* defend against: malware running as you. Anything with your
uid can read the vault file and can talk to the agent while it is unlocked.
That is the bargain every local password manager makes.

**Back up `~/.tvault/vault.json`.** Lose it or forget the master password and
the contents are gone — there is deliberately no recovery path.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Layout

```
tvault/              the Python package
extension/           unpacked Chrome extension
tests/               unit, integration and end-to-end tests
scripts/             icon and extension-key generators

~/.tvault/
  vault.json         your encrypted vault (0600)
  agent.sock         unlock agent socket (0600)
  bin/               generated launchers
```

Both `TVAULT_HOME` and `TVAULT_VAULT` are honoured, which is handy for keeping
a scratch vault while developing.

## Tests

```sh
make test    # 49 unit + native-host integration tests
make e2e     # drives the real CLI through a pty, 17 steps
make lint    # pyflakes
```

Code generation is checked against every RFC 6238 TOTP vector (SHA-1, SHA-256
and SHA-512) and the RFC 4226 HOTP vectors. The vault tests assert that no
plaintext survives in the file, that tampering with either the ciphertext or
the KDF parameters is detected, and that the agent never writes the key to
disk. The native-host tests spawn a real subprocess and speak Chrome's actual
framed protocol to it.

## Troubleshooting

**`zsh: command not found: tvault`** — the launcher lives in `~/.tvault/bin`.
Add it to your `PATH` (see Install) and start a new shell, or run `make path`
for the exact line.

**"Native host not reachable"** — run `tvault install-chrome`, then reload the
extension at `chrome://extensions`. If you loaded it from a different folder,
its ID won't match the one the host allows; compare against
`tvault extension-id`.

**Fill didn't find the fields** — some login pages render the password field
only after you submit the username. Fill the username, continue, then fill
again. If a site is consistently wrong, an issue with the field markup is very
welcome.

**`ensurepip`/`venv` fails** — that is a broken Python installation rather than
a tvault problem. On macOS with Homebrew, `brew reinstall python@3.13` usually
fixes it; you can also point the Makefile at another interpreter with
`make bootstrap PYTHON=python3.12`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Autofill fixes for stubborn login
pages, Firefox support, and rendering an entry back out as a QR code are all
on the wish list.

## License

MIT — see [LICENSE](LICENSE).
