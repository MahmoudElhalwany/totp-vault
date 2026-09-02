# Contributing

Contributions are welcome — bug reports, autofill fixes for stubborn login
pages, and platform support in particular.

## Getting set up

```sh
git clone https://github.com/MahmoudElhalwany/tvault.git
cd tvault
make bootstrap     # venv + native host
make init          # creates a vault; use a throwaway password for development
```

Point tvault at a scratch vault so you never test against your real one:

```sh
export TVAULT_HOME=/tmp/tvault-dev
export TVAULT_VAULT=/tmp/tvault-dev/vault.json
```

## How changes land

`main` is protected: no direct pushes, and every pull request needs a green CI
run across Linux and macOS plus one approving review before it can merge.
Conversations must be resolved, and history is kept linear — squash or rebase
rather than merge commits.

```sh
git checkout -b fix/autofill-on-example-com
# ... work, commit ...
git push -u origin fix/autofill-on-example-com
gh pr create
```

## Before opening a pull request

```sh
make lint    # pyflakes
make test    # unit + native-host integration tests
make e2e     # drives the real CLI through a pty
```

All three should pass. CI runs them on Linux and macOS across Python
3.10–3.13.

## What a good change looks like

- **Add a test.** Anything touching crypto, the vault format, or the native
  host protocol needs one. `tests/test_tvault.py` has the patterns.
- **Keep the vault format versioned.** `FORMAT_VERSION` in `tvault/vault.py`
  exists so old files can be detected. If you change the format, bump it and
  handle the old version rather than breaking existing vaults.
- **Don't widen the extension's permissions** without saying why in the PR.
  The current set is deliberately minimal, and `tests/test_extension.py`
  asserts it.
- **Never let a secret reach stdout in the native host.** It speaks a framed
  protocol; a stray `print` corrupts the stream. Use `stderr`.
- **Keep secrets out of anything the popup renders before confirmation.**
  `scan_qr` previews deliberately carry only the issuer and account name;
  `tests/test_qr.py` asserts it.
- Match the surrounding style. No formatter is enforced; the code is plain
  Python with comments that explain *why*, not *what*.

## Areas that could use help

- Autofill heuristics for sites where `Fill` picks the wrong field.
- Rendering an entry as a QR code for moving a seed back to a phone.
- A pure-Python QR decoder, so `--qr` needs no optional dependency.
- Firefox support — the native messaging protocol is nearly identical, but the
  manifest location and the ID scheme differ.
- Linux testing. The code paths exist and CI covers them, but real-world use
  reports are welcome.
