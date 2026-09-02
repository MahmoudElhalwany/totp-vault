"""Command-line interface for tvault."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
from pathlib import Path

from . import agent, clip, otpauth, ui
from .crypto import VaultCryptoError, gen_passphrase, gen_password
from .vault import (
    Entry,
    Vault,
    VaultError,
    default_vault_path,
    derive_from_header,
    ensure_home,
    read_header,
)


class Locked(Exception):
    """Raised when the vault is locked and prompting is not allowed."""


# -- unlocking ------------------------------------------------------------


def prompt_password(prompt: str = "Master password: ") -> str:
    if not sys.stdin.isatty():
        # Allow piping a password in for scripting, e.g. `echo pw | tvault ls`.
        line = sys.stdin.readline()
        if not line:
            raise VaultError("no password supplied on stdin")
        return line.rstrip("\n")
    return getpass.getpass(prompt)


def prompt_new_password() -> str:
    while True:
        first = getpass.getpass("New master password: ")
        if len(first) < 8:
            ui.warn("use at least 8 characters")
            continue
        second = getpass.getpass("Confirm: ")
        if first != second:
            ui.warn("passwords did not match, try again")
            continue
        return first


def open_vault(path: Path, ttl: int = agent.DEFAULT_TTL, allow_prompt: bool = True) -> tuple[Vault, bytes]:
    """Return a decrypted vault, using the agent's cached key when available."""
    cached = agent.get_key(path)
    if cached:
        try:
            return Vault.load(path, cached), cached
        except VaultCryptoError:
            agent.lock()  # cached key no longer matches this vault

    if not allow_prompt:
        raise Locked("vault is locked")

    header = read_header(path)
    password = prompt_password()
    key = derive_from_header(password, header)
    vault = Vault.load(path, key)  # raises VaultCryptoError on a bad password
    agent.cache_key(key, path, ttl)
    return vault, key


# -- commands -------------------------------------------------------------


def cmd_init(args) -> int:
    path = args.vault
    if path.exists():
        ui.err(f"vault already exists at {path}")
        return 1
    ensure_home()
    print(f"Creating a new vault at {ui.BOLD}{path}{ui.RESET}")
    print(ui.DIM + "This password encrypts everything. It cannot be recovered." + ui.RESET)
    password = prompt_new_password()
    vault, key = Vault.create(path, password)
    agent.cache_key(key, path, args.ttl)
    ui.ok(f"vault created at {path}")
    ui.info("next: tvault add --uri 'otpauth://totp/...'   or   tvault add --interactive")
    return 0


def _entry_from_args(args, vault: Vault) -> list[Entry]:
    """Build entries from a URI, from flags, or by asking interactively."""
    if args.uri:
        text = args.uri
        if text == "-":
            text = sys.stdin.read()
        parsed = otpauth.parse_any(text)
        return [_entry_from_parsed(p, args) for p in parsed]

    if args.interactive or args.kind or not args.name:
        return [_interactive_entry(args)]

    entry = Entry(
        name=args.name,
        issuer=args.issuer or args.name,
        username=args.username or "",
        urls=list(args.url or []),
        notes=args.notes or "",
    )
    if args.secret:
        parsed = otpauth.parse_uri(
            f"otpauth://totp/{args.name}?secret={args.secret}"
        )
        entry.secret = parsed["secret"]
        entry.algorithm = args.algorithm
        entry.digits = args.digits
        entry.period = args.period
    if args.gen_password:
        entry.password = gen_password(args.gen_password)
        ui.info(f"generated a {args.gen_password}-character password")
    elif args.password:
        entry.password = prompt_password("Password for this entry: ")
    return [entry]


def _entry_from_parsed(parsed: dict, args) -> Entry:
    return Entry(
        name=parsed["name"],
        issuer=parsed["issuer"],
        username=parsed["username"],
        secret=parsed["secret"],
        type=parsed["type"],
        algorithm=parsed["algorithm"],
        digits=parsed["digits"],
        period=parsed["period"],
        counter=parsed["counter"],
        urls=list(args.url or []),
    )


def _interactive_entry(args) -> Entry:
    """Ask only for the fields the entry actually needs.

    A TOTP-only entry should not be dragged through username and password
    prompts, so the kind is settled first and everything irrelevant to it is
    skipped. An otpauth:// URI carries the issuer and account, so pasting one
    answers the naming questions too.
    """

    def ask(label: str, default: str = "", optional: bool = False) -> str:
        if default:
            suffix = f" [{default}]"
        elif optional:
            suffix = f" {ui.GREY}(optional){ui.RESET}"
        else:
            suffix = ""
        return input(f"{label}{suffix}: ").strip() or default

    kind = args.kind
    if not kind:
        print(f"{ui.BOLD}What are you adding?{ui.RESET}")
        print(f"  {ui.CYAN}1{ui.RESET}  authenticator code only")
        print(f"  {ui.CYAN}2{ui.RESET}  login (username + password)")
        print(f"  {ui.CYAN}3{ui.RESET}  both")
        kind = {"1": "otp", "2": "login", "3": "both"}.get(ask("choice", "1"), "otp")
        print()

    entry = Entry(name=args.name or "", issuer=args.issuer or "", username=args.username or "")

    if kind in ("otp", "both"):
        while True:
            raw = args.secret or ask("Secret or otpauth:// URI")
            args.secret = None
            if not raw:
                ui.warn("a secret is required for an authenticator entry")
                continue
            try:
                if raw.lower().startswith("otpauth"):
                    parsed = otpauth.parse_any(raw)[0]
                else:
                    parsed = otpauth.parse_uri(f"otpauth://totp/account?secret={raw}")
                    parsed["name"] = parsed["issuer"] = parsed["username"] = ""
                break
            except (otpauth.OtpAuthError, ValueError) as exc:
                ui.warn(str(exc))

        entry.secret = parsed["secret"]
        entry.type = parsed["type"]
        entry.algorithm = parsed["algorithm"]
        entry.digits = parsed["digits"]
        entry.period = parsed["period"]
        entry.counter = parsed["counter"]
        entry.name = entry.name or parsed["name"]
        entry.issuer = entry.issuer or parsed["issuer"]
        entry.username = entry.username or parsed["username"]
        if entry.name:
            print(f"  {ui.GREEN}→{ui.RESET} {entry.label}")

    if not entry.name:
        entry.name = ask("Name")
        if not entry.name:
            raise VaultError("a name is required")
    if not entry.issuer:
        entry.issuer = entry.name

    if kind in ("login", "both"):
        if not entry.username:
            entry.username = ask("Username or email", optional=(kind == "both"))
        choice = ask("Password — (t)ype or (g)enerate", "g")
        if choice.lower().startswith("g"):
            entry.password = gen_password(24)
            ui.info("generated a 24-character password")
        elif choice.lower().startswith("t"):
            entry.password = getpass.getpass("Password: ")

    if args.url:
        entry.urls = list(args.url)
    else:
        url = ask("Website for browser autofill", optional=True)
        if url:
            entry.urls = [url]

    return entry


def cmd_add(args) -> int:
    vault, key = open_vault(args.vault, args.ttl)
    entries = _entry_from_args(args, vault)
    added = []
    for entry in entries:
        try:
            vault.add(entry, replace=args.force)
        except VaultError as exc:
            ui.warn(str(exc))
            continue
        added.append(entry)
    if not added:
        ui.err("nothing added")
        return 1
    vault.save(key)
    for entry in added:
        bits = []
        if entry.has_totp:
            bits.append("TOTP")
        if entry.has_password:
            bits.append("password")
        ui.ok(f"added {ui.BOLD}{entry.name}{ui.RESET} ({', '.join(bits) or 'no secrets'})")
    return 0


def cmd_list(args) -> int:
    vault, _ = open_vault(args.vault, args.ttl)
    entries = vault.search(args.query) if args.query else vault.sorted_entries()
    if args.host:
        entries = vault.for_host(args.host)

    if args.json:
        print(json.dumps([e.public() for e in entries], indent=2))
        return 0
    if not entries:
        ui.info("no entries")
        return 0

    rows = []
    for entry in sorted(entries, key=lambda e: (e.issuer or e.name).lower()):
        marks = []
        if entry.has_totp:
            marks.append(f"{ui.CYAN}otp{ui.RESET}")
        if entry.has_password:
            marks.append(f"{ui.YELLOW}pw{ui.RESET}")
        rows.append([
            entry.name,
            ui.truncate(entry.username, 28),
            " ".join(marks),
            ui.GREY + ui.truncate(", ".join(entry.urls), 30) + ui.RESET,
        ])
    print(ui.table(rows, ["NAME", "USERNAME", "HAS", "URLS"]))
    print(f"\n{ui.DIM}{len(entries)} entr{'y' if len(entries) == 1 else 'ies'}{ui.RESET}")
    return 0


def cmd_code(args) -> int:
    vault, key = open_vault(args.vault, args.ttl)
    entry = vault.resolve(args.query)
    if not entry.has_totp:
        ui.err(f"{entry.name!r} has no TOTP secret")
        return 1

    code = entry.code()
    if entry.type == "hotp":
        entry.counter += 1
        vault.save(key)

    if args.quiet:
        print(code)
        return 0

    left = int(entry.remaining())
    colour = ui.RED if left <= 5 else ui.CYAN
    print(f"{ui.BOLD}{entry.label}{ui.RESET}")
    print(f"  {colour}{ui.BOLD}{ui.group_code(code)}{ui.RESET}  {ui.bar(entry.remaining() / entry.period)} {ui.GREY}{left}s left{ui.RESET}")

    if not args.no_copy:
        try:
            clip.copy_with_clear(code, args.clear)
            ui.info(f"copied to clipboard (clears in {args.clear}s)")
        except (clip.ClipboardUnavailable, OSError) as exc:
            ui.warn(str(exc))
    return 0


def cmd_pass(args) -> int:
    vault, _ = open_vault(args.vault, args.ttl)
    entry = vault.resolve(args.query)
    if not entry.has_password:
        ui.err(f"{entry.name!r} has no password")
        return 1
    if args.show:
        print(entry.password)
        return 0
    try:
        clip.copy_with_clear(entry.password, args.clear)
        ui.ok(f"password for {ui.BOLD}{entry.label}{ui.RESET} copied (clears in {args.clear}s)")
    except (clip.ClipboardUnavailable, OSError) as exc:
        ui.err(str(exc))
        return 1
    return 0


def cmd_show(args) -> int:
    vault, _ = open_vault(args.vault, args.ttl)
    entry = vault.resolve(args.query)
    rows = [
        ["name", entry.name],
        ["issuer", entry.issuer or ui.GREY + "—" + ui.RESET],
        ["username", entry.username or ui.GREY + "—" + ui.RESET],
        ["password", (ui.YELLOW + "••••••••" + ui.RESET) if entry.has_password else ui.GREY + "—" + ui.RESET],
        ["urls", ", ".join(entry.urls) or ui.GREY + "—" + ui.RESET],
        ["notes", entry.notes or ui.GREY + "—" + ui.RESET],
        ["id", ui.GREY + entry.id + ui.RESET],
    ]
    if entry.has_totp:
        rows.insert(4, ["otp", f"{entry.type.upper()} {entry.algorithm} {entry.digits} digits / {entry.period}s"])
        if args.secret:
            rows.insert(5, ["secret", ui.RED + entry.secret + ui.RESET])
            rows.insert(6, ["uri", ui.GREY + otpauth.build_uri(entry.to_dict()) + ui.RESET])
    print(ui.table(rows))
    return 0


def cmd_watch(args) -> int:
    vault, _ = open_vault(args.vault, args.ttl)
    entries = [e for e in (vault.search(args.query) if args.query else vault.entries) if e.has_totp]
    ui.watch(sorted(entries, key=lambda e: (e.issuer or e.name).lower()))
    return 0


def cmd_rm(args) -> int:
    vault, key = open_vault(args.vault, args.ttl)
    entry = vault.resolve(args.query)
    if not args.yes:
        answer = input(f"Delete {ui.BOLD}{entry.label}{ui.RESET}? this cannot be undone [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            ui.info("cancelled")
            return 1
    vault.remove(entry)
    vault.save(key)
    ui.ok(f"deleted {entry.name}")
    return 0


def cmd_edit(args) -> int:
    vault, key = open_vault(args.vault, args.ttl)
    entry = vault.resolve(args.query)
    changed = []

    for attr in ("name", "issuer", "username", "notes"):
        value = getattr(args, attr, None)
        if value is not None:
            setattr(entry, attr, value)
            changed.append(attr)
    if args.url:
        entry.urls = list(args.url)
        changed.append("urls")
    if args.add_url:
        entry.urls = sorted(set(entry.urls) | set(args.add_url))
        changed.append("urls")
    if args.gen_password:
        entry.password = gen_password(args.gen_password)
        changed.append("password")
    elif args.password:
        entry.password = getpass.getpass("New password: ")
        changed.append("password")
    if args.secret:
        otpauth.parse_uri(f"otpauth://totp/x?secret={args.secret}")
        entry.secret = args.secret.replace(" ", "").upper()
        changed.append("secret")
    if args.clear_password:
        entry.password = ""
        changed.append("password")
    if args.clear_totp:
        entry.secret = ""
        changed.append("secret")

    if not changed:
        ui.err("nothing to change — pass at least one field flag (see --help)")
        return 1
    entry.updated = int(time.time())
    vault.save(key)
    ui.ok(f"updated {entry.name}: {', '.join(sorted(set(changed)))}")
    return 0


def cmd_gen(args) -> int:
    if args.words:
        print(gen_passphrase(args.words))
        return 0
    password = gen_password(args.length, symbols=not args.no_symbols, unambiguous=args.unambiguous)
    print(password)
    if args.copy:
        try:
            clip.copy_with_clear(password, args.clear)
            ui.info(f"copied (clears in {args.clear}s)")
        except (clip.ClipboardUnavailable, OSError) as exc:
            ui.warn(str(exc))
    return 0


def cmd_import(args) -> int:
    vault, key = open_vault(args.vault, args.ttl)
    text = sys.stdin.read() if args.file == "-" else Path(args.file).read_text(encoding="utf-8")

    imported = []
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = None

    if isinstance(payload, dict) and "entries" in payload:
        candidates = [Entry.from_dict(e) for e in payload["entries"]]
    elif isinstance(payload, list):
        candidates = [Entry.from_dict(e) for e in payload]
    else:
        candidates = [_entry_from_parsed(p, args) for p in otpauth.parse_any(text)]

    for entry in candidates:
        entry.id = Entry(name=entry.name).id  # fresh id, avoid collisions
        try:
            vault.add(entry, replace=args.force)
            imported.append(entry)
        except VaultError as exc:
            ui.warn(str(exc))
    if not imported:
        ui.err("nothing imported")
        return 1
    vault.save(key)
    ui.ok(f"imported {len(imported)} entr{'y' if len(imported) == 1 else 'ies'}")
    for entry in imported:
        print(f"  {ui.DIM}·{ui.RESET} {entry.label}")
    return 0


def cmd_export(args) -> int:
    vault, _ = open_vault(args.vault, args.ttl)
    entries = vault.search(args.query) if args.query else vault.entries

    if not args.yes:
        ui.warn("this writes secrets in PLAINTEXT")
        if input("continue? [y/N] ").strip().lower() not in ("y", "yes"):
            ui.info("cancelled")
            return 1

    if args.format == "uri":
        lines = [otpauth.build_uri(e.to_dict()) for e in entries if e.has_totp]
        output = "\n".join(lines) + "\n"
    else:
        output = json.dumps({"entries": [e.to_dict() for e in entries]}, indent=2) + "\n"

    if args.out:
        path = Path(args.out)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(output)
        ui.ok(f"exported {len(entries)} entries to {path} (mode 0600)")
    else:
        sys.stdout.write(output)
    return 0


def cmd_passwd(args) -> int:
    vault, _ = open_vault(args.vault, args.ttl)
    ui.info("re-encrypting the vault with a new master password")
    new_key = vault.rekey(prompt_new_password())
    vault.save(new_key)
    agent.cache_key(new_key, args.vault, args.ttl)
    ui.ok("master password changed")
    return 0


def cmd_unlock(args) -> int:
    vault, key = open_vault(args.vault, args.ttl)
    state = agent.status()
    ui.ok(f"unlocked — {len(vault.entries)} entries, locks after {state.get('ttl', args.ttl)}s idle")
    return 0


def cmd_lock(args) -> int:
    if agent.lock():
        ui.ok("locked")
    else:
        ui.info("already locked")
    return 0


def cmd_status(args) -> int:
    state = agent.status()
    path = args.vault
    rows = [
        ["vault", str(path)],
        ["exists", (ui.GREEN + "yes" + ui.RESET) if path.exists() else (ui.RED + "no" + ui.RESET)],
        ["agent", (ui.GREEN + "running" + ui.RESET) if state.get("running") else ui.GREY + "not running" + ui.RESET],
        ["state", (ui.GREEN + "unlocked" + ui.RESET) if state.get("unlocked") else (ui.YELLOW + "locked" + ui.RESET)],
    ]
    if state.get("unlocked"):
        rows.append(["locks in", f"{state.get('expires_in', 0)}s"])
    print(ui.table(rows))
    return 0


def cmd_install_chrome(args) -> int:
    from . import install

    return install.install_chrome(args)


def cmd_uninstall_chrome(args) -> int:
    from . import install

    return install.uninstall_chrome(args)


def cmd_extension_id(args) -> int:
    from . import install

    print(install.extension_id())
    return 0


# -- argument parsing -----------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tvault",
        description="Local encrypted TOTP + password vault.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  tvault init\n"
            "  tvault add --uri 'otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP&issuer=GitHub'\n"
            "  tvault add --interactive\n"
            "  tvault code github            # prints + copies the current code\n"
            "  tvault watch                  # live view of every code\n"
            "  tvault pass github            # copy the password\n"
            "  tvault install-chrome         # wire up the browser extension\n"
        ),
    )
    parser.add_argument("--vault", type=Path, default=None, help="path to the vault file")
    parser.add_argument("--ttl", type=int, default=agent.DEFAULT_TTL, help="agent idle timeout in seconds")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    def add(name, func, help_text, **kwargs):
        p = sub.add_parser(name, help=help_text, description=help_text, **kwargs)
        p.set_defaults(func=func)
        return p

    add("init", cmd_init, "create a new encrypted vault")

    p = add("add", cmd_add, "add an entry (from a URI, flags, or interactively)")
    p.add_argument("name", nargs="?", help="entry name, e.g. GitHub")
    p.add_argument("--uri", help="otpauth:// or otpauth-migration:// URI, or '-' to read stdin")
    p.add_argument("-i", "--interactive", action="store_true", help="prompt for the fields this entry needs")
    p.add_argument("--otp", dest="kind", action="store_const", const="otp",
                   help="interactive: authenticator code only, skip login prompts")
    p.add_argument("--login", dest="kind", action="store_const", const="login",
                   help="interactive: username and password only, skip the code prompt")
    p.add_argument("--both", dest="kind", action="store_const", const="both",
                   help="interactive: code plus login")
    p.add_argument("--issuer")
    p.add_argument("-u", "--username")
    p.add_argument("-s", "--secret", help="base32 TOTP secret")
    p.add_argument("--algorithm", default="SHA1", choices=["SHA1", "SHA256", "SHA512"])
    p.add_argument("--digits", type=int, default=6, choices=[6, 7, 8])
    p.add_argument("--period", type=int, default=30)
    p.add_argument("-p", "--password", action="store_true", help="prompt for a password to store")
    p.add_argument("-g", "--gen-password", type=int, nargs="?", const=24, metavar="LEN",
                   help="generate and store a password")
    p.add_argument("--url", action="append", help="site this entry belongs to (repeatable)")
    p.add_argument("--notes")
    p.add_argument("-f", "--force", action="store_true", help="replace an existing entry with the same name")

    p = add("ls", cmd_list, "list entries", aliases=["list"])
    p.add_argument("query", nargs="?")
    p.add_argument("--host", help="only entries matching this website host")
    p.add_argument("--json", action="store_true")

    p = add("code", cmd_code, "print and copy the current TOTP code", aliases=["otp"])
    p.add_argument("query")
    p.add_argument("-n", "--no-copy", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true", help="print only the code")
    p.add_argument("--clear", type=int, default=30, help="clipboard auto-clear seconds")

    p = add("pass", cmd_pass, "copy an entry's password to the clipboard")
    p.add_argument("query")
    p.add_argument("--show", action="store_true", help="print instead of copying")
    p.add_argument("--clear", type=int, default=30)

    p = add("show", cmd_show, "show one entry's details")
    p.add_argument("query")
    p.add_argument("--secret", action="store_true", help="reveal the TOTP secret and URI")

    p = add("watch", cmd_watch, "live-refreshing view of all codes")
    p.add_argument("query", nargs="?")

    p = add("rm", cmd_rm, "delete an entry", aliases=["remove"])
    p.add_argument("query")
    p.add_argument("-y", "--yes", action="store_true")

    p = add("edit", cmd_edit, "change fields on an existing entry")
    p.add_argument("query")
    p.add_argument("--name")
    p.add_argument("--issuer")
    p.add_argument("--username")
    p.add_argument("--notes")
    p.add_argument("--url", action="append", help="replace the URL list")
    p.add_argument("--add-url", action="append", help="append a URL")
    p.add_argument("-p", "--password", action="store_true", help="prompt for a new password")
    p.add_argument("-g", "--gen-password", type=int, nargs="?", const=24, metavar="LEN")
    p.add_argument("-s", "--secret", help="replace the TOTP secret")
    p.add_argument("--clear-password", action="store_true")
    p.add_argument("--clear-totp", action="store_true")

    p = add("gen", cmd_gen, "generate a password or passphrase")
    p.add_argument("-l", "--length", type=int, default=24)
    p.add_argument("-w", "--words", type=int, nargs="?", const=5, metavar="N", help="passphrase instead")
    p.add_argument("--no-symbols", action="store_true")
    p.add_argument("--unambiguous", action="store_true", help="avoid lookalike characters")
    p.add_argument("-c", "--copy", action="store_true")
    p.add_argument("--clear", type=int, default=30)

    p = add("import", cmd_import, "import entries from JSON or otpauth URIs")
    p.add_argument("file", help="file path, or '-' for stdin")
    p.add_argument("--url", action="append")
    p.add_argument("-f", "--force", action="store_true")

    p = add("export", cmd_export, "export entries in PLAINTEXT (use with care)")
    p.add_argument("query", nargs="?")
    p.add_argument("--format", choices=["json", "uri"], default="json")
    p.add_argument("--out")
    p.add_argument("-y", "--yes", action="store_true")

    add("passwd", cmd_passwd, "change the master password")

    p = add("unlock", cmd_unlock, "unlock the vault and cache the key in the agent")
    add("lock", cmd_lock, "forget the cached key immediately")
    add("status", cmd_status, "show vault and agent status")

    p = add("install-chrome", cmd_install_chrome, "install the Chrome native messaging host")
    p.add_argument("--browser", action="append",
                   help="chrome, chrome-beta, chromium, edge, brave, vivaldi (default: all found)")
    add("uninstall-chrome", cmd_uninstall_chrome, "remove the native messaging host")
    add("extension-id", cmd_extension_id, "print the extension's deterministic ID")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    if args.vault is None:
        args.vault = default_vault_path()

    try:
        return args.func(args)
    except (VaultError, VaultCryptoError, otpauth.OtpAuthError, ValueError) as exc:
        ui.err(str(exc))
        return 1
    except Locked as exc:
        ui.err(str(exc))
        return 2
    except KeyboardInterrupt:
        print()
        return 130
    except BrokenPipeError:
        return 0
