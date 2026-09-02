"""Drive the real tvault CLI through a pty, as an interactive terminal would.

Covers what the unit tests cannot: the argparse surface, interactive password
prompts, and the agent lock/unlock lifecycle across separate processes.
"""
import os, pty, re, select, subprocess, sys, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
tmp = tempfile.mkdtemp(prefix="tvault-e2e-")
ENV = {**os.environ, "TVAULT_HOME": tmp, "TVAULT_VAULT": f"{tmp}/vault.json",
       "PYTHONPATH": str(ROOT), "NO_COLOR": "1", "TERM": "dumb"}
PW = "e2e master password"

def run_pty(args, inputs, timeout=30):
    """Run tvault under a pty, feeding `inputs` lines as prompts appear."""
    pid, fd = pty.fork()
    if pid == 0:
        os.execve(PY, [PY, "-m", "tvault", *args], ENV)

    out, queue, deadline, status = b"", list(inputs), time.time() + timeout, None
    while time.time() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.4)
        if ready:
            try:
                chunk = os.read(fd, 4096)
            except OSError:      # pty closed: the child exited
                break
            if not chunk:
                break
            out += chunk
        elif queue:
            os.write(fd, (queue.pop(0) + "\n").encode())
            time.sleep(0.15)
        else:
            done, status = os.waitpid(pid, os.WNOHANG)
            if done:
                break
    try:
        os.close(fd)
    except OSError:
        pass
    if status is None:
        _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status), out.decode("utf-8", "replace")


def run(args, stdin=None):
    p = subprocess.run([PY, "-m", "tvault", *args], env=ENV, capture_output=True,
                       input=(stdin.encode() if stdin else None), timeout=30)
    return p.returncode, p.stdout.decode() + p.stderr.decode()

def step(label, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok and detail:
        print("        " + detail.replace("\n", "\n        ")[:900])
    return ok

results = []
print(f"\nsandbox: {tmp}\n")

# 1. init (interactive: new password + confirm)
rc, out = run_pty(["init"], [PW, PW])
results.append(step("tvault init", "vault created" in out, out))

# 2. add from an otpauth URI
rc, out = run(["add", "--uri", "otpauth://totp/GitHub:me@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
               "--url", "github.com"], stdin=PW)
results.append(step("tvault add --uri", rc == 0 and "added" in out, out))

# 3. add with a generated password
rc, out = run(["add", "AWS", "--username", "root@example.com", "-g", "32", "--url", "aws.amazon.com"])
results.append(step("tvault add -g (generated password)", rc == 0 and "added" in out, out))

# 4. Google Authenticator export import
import base64
def varint(v):
    o = bytearray()
    while True:
        b = v & 0x7F; v >>= 7; o.append(b | (0x80 if v else 0))
        if not v: return bytes(o)
def delim(n, p): return varint((n << 3) | 2) + varint(len(p)) + p
acct = delim(1, base64.b32decode("JBSWY3DPEHPK3PXP")) + delim(2, b"work@example.com") + delim(3, b"Okta") \
     + varint((4 << 3)) + varint(1) + varint((5 << 3)) + varint(1) + varint((6 << 3)) + varint(2)
mig = "otpauth-migration://offline?data=" + base64.b64encode(delim(1, acct)).decode()
rc, out = run(["import", "-"], stdin=mig)
results.append(step("import Google Authenticator export", rc == 0 and "Okta" in out, out))

# 5. list
rc, out = run(["ls"])
results.append(step("tvault ls shows all three", rc == 0 and all(n in out for n in ("GitHub", "AWS", "Okta")), out))

# 6. host filter
rc, out = run(["ls", "--host", "gist.github.com", "--json"])
results.append(step("tvault ls --host matches subdomain", '"GitHub"' in out and '"AWS"' not in out, out))

# 7. code
rc, out = run(["code", "github", "--no-copy"])
m = re.search(r"(\d{3} \d{3})", out)
results.append(step("tvault code prints a 6-digit code", rc == 0 and bool(m), out))

# 8. code -q pipes cleanly
rc, out = run(["code", "github", "-q", "-n"])
results.append(step("tvault code -q is script-friendly", rc == 0 and bool(re.fullmatch(r"\d{6}\n", out)), repr(out)))

# 9. password retrieval
rc, out = run(["pass", "AWS", "--show"])
results.append(step("tvault pass --show returns the generated password", rc == 0 and len(out.strip()) == 32, out))

# 10. status reflects the unlocked agent
rc, out = run(["status"])
results.append(step("tvault status reports unlocked", "unlocked" in out, out))

# 11. lock, then a locked read must re-prompt (and succeed with piped password)
run(["lock"])
rc, out = run(["ls"], stdin=PW)
results.append(step("re-unlock after lock", rc == 0 and "GitHub" in out, out))

# 12. wrong password is refused
rc, out = run(["--vault", f"{tmp}/vault.json", "ls"], stdin="totally wrong")
run(["lock"])
rc2, out2 = run(["ls"], stdin="totally wrong")
results.append(step("wrong master password refused", rc2 != 0 and "decryption failed" in out2, out2))

# 13. edit
run(["lock"])
rc, out = run(["edit", "AWS", "--add-url", "console.aws.amazon.com"], stdin=PW)
rc2, out2 = run(["show", "AWS"])
results.append(step("tvault edit --add-url", rc == 0 and "console.aws.amazon.com" in out2, out + out2))

# 14. export round-trip
rc, out = run(["export", "--format", "uri", "-y"])
results.append(step("tvault export --format uri", rc == 0 and out.count("otpauth://") == 2, out))

# 15. rm
rc, out = run(["rm", "Okta", "-y"])
rc2, out2 = run(["ls"])
results.append(step("tvault rm", rc == 0 and "Okta" not in out2, out + out2))

# 16. interactive add: an authenticator-only entry must skip the login prompts
URI = "otpauth://totp/Okta:work@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Okta"
rc, out = run_pty(["add", "-i"], ["1", URI, "okta.example"])
results.append(step("interactive add (code only) skips username/password",
                    "added" in out and "Username" not in out and "Password" not in out
                    and "Okta (work@example.com)" in out, out))

# 17. --otp bypasses the kind menu
rc, out = run_pty(["add", "--otp"], ["JBSWY3DPEHPK3PXP", "Stripe", ""])
results.append(step("add --otp skips the menu entirely",
                    "added" in out and "What are you adding" not in out
                    and "Password" not in out, out))

# 18. --login never asks for a secret
rc, out = run_pty(["add", "--login"], ["Bank", "acct@example.com", "g", "bank.example"])
results.append(step("add --login skips the secret prompt",
                    "added" in out and "Secret" not in out and "password" in out, out))

# 19. change master password
rc, out = run_pty(["passwd"], ["new master password", "new master password"])
run(["lock"])
rc2, out2 = run(["ls"], stdin="new master password")
run(["lock"])  # must re-prompt, or the cached key masks the result
rc3, out3 = run(["ls"], stdin=PW)
results.append(step("tvault passwd re-encrypts with the new password",
                    "GitHub" in out2 and rc3 != 0 and "decryption failed" in out3, out + out2 + out3))

# 20. gen
rc, out = run(["gen", "-l", "40", "--unambiguous"])
results.append(step("tvault gen", rc == 0 and len(out.strip()) == 40 and not (set(out.strip()) & set("lI1O0")), out))

run(["lock"])
print(f"\n{sum(results)}/{len(results)} CLI steps passed\n")
sys.exit(0 if all(results) else 1)
