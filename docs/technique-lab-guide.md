# Technique lab guide: how each behaviour works, and how to test it safely

`docs/gap-register.md` G-01 says it plainly: every one of the 39 fixtures is
`designed`, derived from its rule, so a green fixture proves the rule is
internally consistent and nothing more. Only a real host can close that. This
page is the bridge — for each technique the rules cover, **what the behaviour
actually is**, **why the telemetry looks the way it does**, and **the smallest
safe experiment that produces it**.

## The rule this page follows

Every test below is one of three things:

1. **A Microsoft-signed binary doing the same thing.** `rundll32` loading an
   export is how legitimate software works; it is also how a loader works. The
   telemetry is identical, which is exactly the point.
2. **A published, maintained test from Atomic Red Team.** These exist so that
   defenders can generate technique telemetry without writing an implant. Run
   them from a checkout on an isolated VM.
3. **A source string in this repository, compiled on the VM.** For the YARA
   cases, the repo ships *detection* strings; the harmless test binary is built
   there, from a source file you can read in a few minutes.

Nothing here needs a working implant, and there is deliberately no section that
explains how to *build* one. The distinction that matters: this page explains
the **mechanism** (so a detection can be reasoned about) without providing an
**implementation** (a dropper that runs end to end). See `SCOPE.md`.

## Before you start

- Isolated VM, Internal Network or Host-only. Never Bridged — `lab-setup.md`
  explains why.
- Sysmon installed with `telemetry/sysmon-config.xml`, hash-pinned in
  `baseline/manifest.json`. A rejected config silently falls back to a default
  that matches none of these rules.
- `telemetry/auditpol.md` applied, including `deploy/telemetry/set-sacls.ps1`
  for the one rule that needs a SACL.
- Snapshot first. Some of these change persistence and you will want the
  pre-test state back.
- Take a 24-hour clean baseline **before** any of it (G-02). Without it you
  cannot tell a true positive from your own test.

Check what you should expect by event ID before you run anything:

```bash
python3 tools/capture_kit.py --rule <id-prefix>
```

That prints the event IDs to collect, the fields the rule reads, and which
inert emulator command produces the behaviour in the repo's own emulator.

---

## The techniques, one at a time

### T1059 — Interpreter and script-host child processes

**What it is.** The implant is not a compiled binary with a recognisable import
table. It is a script — Python, or PowerShell — running under an interpreter that
is signed by Microsoft or a legitimate vendor. The executable that appears in
Sysmon is `python.exe` or `powershell.exe`; the code that matters is never on
disk.

**Why the telemetry is only a shape.** `python_parent_child_shape.yml` does not
match a string; it matches a *process tree*: a Python process whose parent is not
a Python process, spawning a child that is a Windows utility (`cmd.exe`,
`whoami.exe`, `nltest.exe`). That tree is what a scripted operator looks like and
what a Python-based application almost never looks like, because applications call
APIs rather than shelling out to `whoami`.

**Safe test.**

```powershell
# A Python process whose parent is PowerShell, spawning a recon child.
python -c "import subprocess; subprocess.run(['whoami.exe'])"
# Expect: Sysmon 1 for python.exe (ParentImage powershell.exe),
#         then Sysmon 1 for whoami.exe (ParentImage python.exe).
```

**The false positive to expect.** Any Python build tool, CI runner or Ansible
module produces this exact tree. The rule is a *lead*, and it is graded as one;
correlate it with the network rules rather than treating it as an alert.

---

### T1547.001 — Registry Run keys and Startup folder

**What it is.** Windows starts anything listed under
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (and the `HKLM`
equivalent, and the Startup folder) at logon. There is no signature check and no
prompt. A program that wants to survive a reboot writes one value here.

**Why the telemetry looks like it does.** Sysmon Event ID 13 (`RegistryEvent —
Value Set`) fires on the write, carrying `TargetObject` and `Details`. The
`Details` field is the command that will run at next logon, verbatim, including
quoting. This is the single highest-signal field in the rule, and it is why the
rule matches on `Details|contains` rather than on the key alone: every installer
writes a Run key, and only some of them write `powershell -enc`.

**What the rule keys on.** `run_key_write.yml` matches a write to the Run key
where the *value* is one of a small set of interpreter/loader images, or where
the `Image` that wrote it is an unsigned binary in a temp path.

**Safe test.**

```powershell
# The write itself, with a harmless payload.
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' `
  -Name 'LabCanary' -Value 'C:\Windows\System32\notepad.exe' -PropertyType String

# Expect: Sysmon 13, TargetObject ending ...\CurrentVersion\Run, Details = notepad path
# The rule should NOT fire: notepad is not an interpreter and the writer is PowerShell, signed.

# Now the shape the rule is for:
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' `
  -Name 'LabCanary2' -Value 'powershell.exe -NoProfile -Command "exit"' -PropertyType String
# Expect: the rule fires on Details containing powershell.exe.

# Cleanup
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'LabCanary','LabCanary2'
```

**The false positive you must expect.** Every software update writes a Run key.
If your precision work (G-03) has not happened, this rule will be noisy, and the
discriminator is the `Image` signature and path, not the key.

**What a real one looks like differently.** Persistence installed by
`schtasks`/`sc` from a user session, or by a process whose `ParentImage` is
Office or a browser. The rule cannot see intent — it sees a process tree.

---

### T1053.005 — Scheduled tasks

**What it is.** `schtasks /create` registers a task the Task Scheduler will run,
optionally at logon or on a schedule, optionally as SYSTEM. Signed, built-in, no
exploit. It is the most common persistence mechanism in real intrusions precisely
because it is so ordinary.

**Why the telemetry looks like it does.** Security 4698 fires on task creation
with the task XML embedded, containing `<Author>`, `<Command>`, `<Arguments>`,
and `<UserId>`. Sysmon also logs it as a file write to
`C:\Windows\System32\Tasks\<name>` — the same task exists as a file on disk, which
is why `schtask_onlogon.yml` can match on `TargetFilename`.

**Safe test.**

```powershell
$action  = New-ScheduledTaskAction -Execute 'notepad.exe'
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName 'LabCanaryTask' -Action $action -Trigger $trigger
# Expect: 4698, and a Sysmon 11 write to C:\Windows\System32\Tasks\LabCanaryTask
Unregister-ScheduledTask -TaskName 'LabCanaryTask' -Confirm:$false
```

**Why the rule reads 4698 and the file write both.** The task *running* later
produces nothing on its own unless process creation auditing is on. The
creation event is the durable evidence.

---

### T1546.003 — WMI event subscription

**What it is.** WMI can call a program when a system event occurs. A
permanent subscription is three objects — an **event filter** (what to watch), an
**event consumer** (what to run), and a **binding** (which wires them) — stored
in the WMI repository. They survive reboots and are invisible to Autoruns,
because Autoruns does not enumerate them.

**Why the telemetry looks like it does.** Each of the three objects produces its
own event: Sysmon 19 (filter), 20 (consumer), 21 (consumer-to-filter binding),
each carrying `EventType`, `Name`, and `Query`/`Destination`/`Consumer`. No
single one is suspicious. The trilogy is: six rules in this repository match the
individual objects, and `wmi_subscription_triple.yml` is the correlation that
requires all three from the same host in a short window.

**Safe test** — build the trilogy and watch all three fire:

```powershell
# 1. The filter: "tell me about process starts"
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter `
  -Arguments @{Name='LabFilter'; EventNamespace='root\cimv2';
               QueryLanguage='WQL';
               Query='SELECT * FROM Win32_ProcessStartTrace'}

# 2. The consumer: "run notepad"
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer `
  -Arguments @{Name='LabConsumer'; CommandLineTemplate='C:\Windows\System32\notepad.exe'}

# 3. The binding
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding `
  -Arguments @{Filter=$filter; Consumer=$consumer}

# Expect: Sysmon 19, 20, 21 in that order, then the triple correlation fires.
# Cleanup — all three must go, in this order:
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding |
  Where-Object {$_.Filter -match 'LabFilter'} | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer |
  Where-Object {$_.Name -eq 'LabConsumer'} | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class __EventFilter |
  Where-Object {$_.Name -eq 'LabFilter'} | Remove-WmiObject
```

**The cleanup trap.** Removing only the filter leaves the consumer and binding,
which is the exact half-cleaned state that makes WMI persistence persist. If
your cleanup was incomplete and the rule fires again after a reboot, that is a
true positive about *you*, not about the test.

---

### T1685 — AMSI and ETW tampering

**What it is.** AMSI (Antimalware Scan Interface) is the API that lets a
scripting host ask "is this string malicious?" before running it. ETW is the
event-tracing pipeline the security product listens on. Both live in memory in
the process that hosts them, so an attacker with code execution in that process
can patch them: resolve `AmsiScanBuffer` inside `amsi.dll`, overwrite its first
bytes with a `mov eax, 0x80070057; ret` (return "invalid argument"), and every
subsequent scan returns an error the host treats as "no opinion".

**Why this is the hardest thing in the repository to detect.** Sysmon has no
event for "a module's code changed". Sysmon 10 (ProcessAccess) fires when a
process *requests a handle* to another process with `GrantedAccess` 0x1F0FFF —
but memory writes inside your own process require no such handle, and the
implant patches its own process. So:

- `amsi_etw_patch.yml` matches Sysmon 8/10 with a `TargetImage` that is a
  scripting host. That catches cross-process attempts.
- The **in-process** case needs EDR module-load and memory telemetry, which this
  lab does not have (G-05). The rule carries the technique tag and is honest
  about being partial.

**Safe test — cross-process only, which is what the telemetry can see.**

```powershell
# Open a handle to notepad with PROCESS_ALL_ACCESS from a different process.
# This is the behaviour Sysmon 10 records; it does no patching.
Add-Type -TypeDefinition @"
using System; using System.Diagnostics;
public class LabAccess {
  public static void Go() {
    var p = Process.Start("notepad.exe");
    System.Threading.Thread.Sleep(500);
    var h = p.Handle;                    // requests full access
    Console.WriteLine("handle: " + h);
    p.Kill();
  }
}
"@
[LabAccess]::Go()
# Expect: Sysmon 10, SourceImage = powershell.exe, TargetImage = notepad.exe,
#         GrantedAccess 0x1FFFFF.
```

**What you are proving and not proving.** You are proving the *detection path*
works — that Sysmon 10 lands with the fields the rule reads, and that the rule
evaluates them. You are not proving the rule catches AMSI patching, because
nothing in this test patched anything. That distinction is the whole of G-05,
and it is why the rule is tagged `partial` rather than claimed.

---

### T1497 — Virtualisation and sandbox checks

**What it is.** Malware asks the environment questions whose answers differ on a
VM: the CPU name string, the number of cores, the disk serial, the presence of a
hypervisor, the MAC OUI prefix. None of these is an exploit; each is a read.

**Why the telemetry looks like it does.** A registry read is not an event Sysmon
produces at all — Sysmon has no "key was read" event. Security 4663 does, but
only when the key carries a SACL. That is precisely what
`deploy/telemetry/set-sacls.ps1` exists to install, and `cpu_info_read.yml`
reads `ObjectName` with `AccessMask` `0x1` — read access — from it.

**Safe test.**

```powershell
# After set-sacls.ps1 has been applied:
Get-ItemProperty 'HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0' |
  Select-Object ProcessorNameString
# Expect: Security 4663, ObjectName containing ...\CentralProcessor\0,
#         AccessMask 0x1, ProcessName = powershell.exe
```

**If no event appears**, the SACL is not installed or the "Registry Object" audit
subcategory is off. Both are silent failures, which is why
`set-sacls.ps1` reads the SACL back and errors rather than reporting success.

---

### T1071.001 — HTTP beaconing with custom headers

**What it is.** An implant that polls a server for commands over HTTPS has to
tell the server which instance it is. The simplest way is a header. The beacon in
this repo's threat model sends `X-Id` (a per-host identifier) and `X-Seq` (a
monotonic counter) on every poll, and deliberately sends **no** `Cookie` and
**no** `Accept-Language`, because its HTTP client is a handful of lines and does
not bother to look like a browser.

**Why the telemetry looks like it does.** Three independent signals, each weak
alone:

| Signal | Where it lives | Why it is weak alone |
|---|---|---|
| The periodic poll | proxy access log timestamps | real software also polls |
| The custom headers | proxy log, *if* headers are retained | most proxies drop unknown headers |
| Absent browser headers | proxy log | curl and API clients also omit them |

`beacon_custom_headers.yml` matches the header pair. `beaconing_frequency.yml`
is a Sigma `event_count` correlation: ≥20 requests to one destination from one
source inside ten minutes. Neither is convincing by itself; `analytics/` has the
inter-arrival analysis (`beacon_jitter.py`) that looks at the *variance* of the
interval, because a scheduler polls at a fixed rate and a human does not.

**Safe test** — a loopback listener and `curl`, no server code needed:

```bash
# On the VM, a listener that prints the request headers
python3 -c "
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        print(dict(self.headers)); self.send_response(200); self.end_headers()
    def log_message(self,*a): pass
socketserver.TCPServer(('127.0.0.1',8080),H).serve_forever()
" &

# Twenty polls, ~5 s apart, with the header pair and no browser headers
for i in $(seq 1 20); do
  curl -s -H "X-Id: lab-vm-01" -H "X-Seq: $i" http://127.0.0.1:8080/poll > /dev/null
  sleep 5
done
```

**Expected telemetry.** The listener prints one line per request carrying
`X-Id` and `X-Seq`; on the VM's own proxy log (if one is in the path) you should
see the same pair with no `Cookie` and no `Accept-Language`. Without a proxy in
the path, nothing in Splunk or Elastic will show anything — see the catch below.

**The catch you will hit.** A loopback request never reaches the proxy, so the
proxy-based rules see nothing. To exercise them you need the request to traverse
a real proxy that logs custom headers — that is G-11, and it means this specific
test only proves the *listener* side. Say so when you record the result.

**The strongest signal, and why it is in `analysis/`.** Poll interval variance.
`analytics/beacon_jitter.py` computes the coefficient of variation over
inter-arrival times; a cron-like scheduler sits near zero. That is behavioural
and survives the attacker changing every string — which is why the docs argue
for it over header matching.

---

### T1568.002 — DGA hostnames

**What it is.** Rather than hardcode a C2 domain that can be seized, the implant
generates one per day from a seed plus the date. The operator registers the day's
name; the defender has to guess it. Detection is statistical, never conclusive:
a random-looking label is a *hint*, and plenty of legitimate domains look random.

**Why two rules, and a burst rule.** `dga_high_entropy_dns.yml` looks at a single
name (length and character mix). `nxdomain_long_label.yml` looks at the *response*
— `NXDOMAIN` for a long random label is the signature of a client asking for
today's name before the operator has registered it. `dns_query_burst_host.yml`
counts: a client asking forty such names in a minute is not a browser.

**Safe test** — query names that cannot resolve, from a host with DNS logging:

```bash
for n in qxzkjvbwprtm sdfjkhqweoiu zxcvbmnbqwer; do
  nslookup "$n.example.invalid" 2>&1 | tail -2
done
# Expect: Zeek dns.log rcode NXDOMAIN, query = <name>.example.invalid,
#         and the burst rule to fire on the count from one Source.
```

`.invalid` is reserved by RFC 2606 and never resolves, so this is a genuinely
safe way to produce the shape. **Do not run it against a corporate resolver** —
forty NXDOMAINs from one host is exactly what a SOC escalation looks like from
the resolver's side.

**The honest limit.** These three rules have no way to know whether a name is
*malicious*, only whether it is *unusual*. Precision here is unknowable without
the benign corpus (G-03), and this is the rule family most likely to be wrong.

---

### T1105 — Ingress tool transfer

**What it is.** Getting a second-stage binary onto the host: a download to a temp
path, an execution from there, or a self-update rewriting its own binary.

**Why the telemetry is thin.** Sysmon 15 (FileCreateStreamHash) and 11 (FileCreate)
see the file land; Sysmon 1 sees it run. Neither sees where it came from unless
the proxy or DNS logs correlate by timestamp. `dropper_unsigned_temp_exec.yml`
joins "file written to `%TEMP%`" with "process started from `%TEMP%` with no valid
signature" — the join is what makes it a signal, since either half alone is
ordinary.

**Safe test.**

```powershell
$p = "$env:TEMP\labcanary.exe"
Copy-Item C:\Windows\System32\notepad.exe $p     # an unsigned-in-TEMP path, harmless binary
& $p; Start-Sleep 2; Get-Process notepad | Stop-Process
# Expect: Sysmon 11 for the write, Sysmon 1 with Image in \Temp\,
#         Signature either absent or "NotSigned".
Remove-Item $p
```

**Why this does not fully test the rule.** Notepad *is* signed, so the signature
predicate will not match honestly. To match it you would need a genuinely unsigned
binary, which means compiling one — see the YARA section for the safe way to do
that from a source file you can read.

---

### T1056.001 — Keylogging by polling

**What it is.** The oldest trick: call `GetAsyncKeyState` in a loop and map the
returned key codes to characters, writing them to a file. No hook, no driver, no
privilege — but it can only capture input to the process that owns the focus, so
real keyloggers usually install a hook (`SetWindowsHookEx`) instead.

**Why the rule is about the output file, not the API.** Sysmon cannot log an API
call. `keylog_encrypted_file.yml` matches the *file* the logger writes: a small
file in a user path, written repeatedly, whose contents are high-entropy (because
real ones are often XOR-encoded on disk). That is inferential and it is honest
about being inferential — a rule matching "a file grew" will match other things
that grow.

**Safe test.**

```powershell
$f = "$env:TEMP\lab-keys.bin"
1..5 | ForEach-Object {
  $bytes = [byte[]](1..2048 | ForEach-Object { Get-Random -Max 256 })
  [IO.File]::WriteAllBytes($f, $bytes)
  Start-Sleep -Milliseconds 400
}
# Expect: repeated Sysmon 11 on the same TargetFilename.
Remove-Item $f
```

**Credential-store specific coverage.** T1555.003 has its own section below
(`Login Data`, DPAPI-wrapped key, and the temp copy that always precedes a read).

**What this does not test.** The API call. Nothing in this repo calls
`GetAsyncKeyState` — that is one of the APIs `tests/test_scope.py` forbids — so
the rule's premise (that a poller exists) is assumed, not demonstrated. G-09
records this.

---

### T1005 — Data from local system (browser stores)

**What it is.** Chromium browsers store saved passwords in an SQLite database,
encrypted with a key held in `Local State` and protected by DPAPI for the logged-in
user. Reading it needs no privilege escalation — just the user's own session,
which is what malware already has — and the file is often copied to a temp path
first because SQLite locking prevents direct reads.

**Why the telemetry is a file *create*.** The copy to `%TEMP%` is Sysmon 11. The
*read* of the original is invisible without a SACL (G-08 covers the machinery;
this specific path is not in the generated script because the rule keys on the
copy, not the read).

**Safe test.**

```powershell
$src = "$env:LOCALAPPDATA\Google\Chrome\User Data\Local State"
if (Test-Path $src) {
  Copy-Item $src "$env:TEMP\lab-localstate.json"
  # Expect: Sysmon 11, TargetFilename = \Temp\lab-localstate.json
  Remove-Item "$env:TEMP\lab-localstate.json"
}
```

**One thing this repo will not do.** Decrypt anything. `CryptUnprotectData` is on
the forbidden list in `tests/test_scope.py`, and the rule detects the *access
pattern*, not the credential. Testing the decryption step is out of scope here and
is what your EDR vendor's test suite is for.

---

### T1113 — Screen capture

**What it is.** `BitBlt` from the screen device context into a bitmap, then saved.
Built into every Windows API set, no special privilege.

**Why the rule keys on the file.** `screenshot_bmp_artifact.yml` matches a `.bmp`
written to a user path — a format almost no modern application writes, because it
is uncompressed. That is the tell.

**Safe test.**

```powershell
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
$b = [Drawing.Bitmap]::new(1920,1080)
[Drawing.Graphics]::FromImage($b).CopyFromScreen(0,0,0,0,$b.Size)
$b.Save("$env:TEMP\lab-shot.bmp")
# Expect: Sysmon 11 for \Temp\lab-shot.bmp
Remove-Item "$env:TEMP\lab-shot.bmp"
```

This uses the managed `CopyFromScreen`, which calls the same `BitBlt` underneath.
The rule does not care which.

---

### T1091 — Removable media spreading

**What it is.** Write an `autorun.inf` to a USB volume and a copy of the payload
next to it. Modern Windows ignores `autorun.inf` on USB for *executable*
launching (since the 2010 update), but it still uses it for icon/label and some
installers, and the *pattern* of a removable volume receiving an `autorun.inf`
plus a new executable is still a spreading signature.

**Why the telemetry is awkward, and why two gaps exist.** Sysmon 11 gives the file
write with a drive letter. A drive letter does not tell you the volume is
removable — `D:` could be a second internal disk. Windows does not put the drive
type in the event. `removable_media_spreader_write.yml` matches the drive-letter
pattern and admits the limitation; G-24 records it, and closing it needs a SIEM-side
join against drive enumeration, which needs a real SIEM.

**Safe test.**

```powershell
$usb = Read-Host "Drive letter of your test USB (e.g. E)"
@"
[autorun]
label=LabCanary
"@ | Set-Content "${usb}:\autorun.inf"
Copy-Item C:\Windows\System32\notepad.exe "${usb}:\labcanary.exe"
# Expect: Sysmon 11 for both writes, TargetFilename on the E: volume
Remove-Item "${usb}:\autorun.inf","${usb}:\labcanary.exe"
```

**Do this only on a USB stick you own and can erase.** `autorun.inf` on a real
stick, carried to another machine, is a genuine (if mild) risk. Prefer a
disposable stick, and format it afterwards.

---

### T1555.003 — Files a browser stores credentials in

**What it is.** Chromium keeps saved logins in `Login Data`, an SQLite database
encrypted with a key wrapped by DPAPI for the current user. Firefox keeps its own
store under `Profiles\`. Neither needs elevation to read from the user's own
session, which is the only session malware needs.

**Why there are two rules.** `credential_file_access.yml` matches the *read* of
`Local State` or `Login Data` (Sysmon 11 on the create of a copy, or 4663 with a
SACL). `sqlite_temp_copy.yml` matches the step that always precedes a successful
read: SQLite locks the live file, so the reader copies it to `%TEMP%` first. The
copy is the more reliable signal, because the copy is unavoidable.

**Safe test.**

```powershell
$profile = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
if (Test-Path $profile) {
  Copy-Item $profile "$env:TEMP\lab-logindata.db"
  # Expect: Sysmon 11, TargetFilename = \Temp\lab-logindata.db
  Remove-Item "$env:TEMP\lab-logindata.db"
}
```

Nothing is decrypted by this test, and nothing in this repository decrypts it.

---

### T1135 — Network share and domain enumeration

**What it is.** `net view` asks the browser service which machines and shares
exist; `nltest /dclist` asks which domain controllers serve the domain. Both are
Microsoft-signed, both are used daily by administrators, and both tell an operator
where to go next.

**Why it is grouped with T1592.002 in the rules but separate here.** The two rules
that read these commands (`net_view_recon.yml`, `wmi_recon_command.yml`) tag both
techniques, because "who am I" and "what is next to me" are answered by the same
commands. The discriminator in both cases is the *parent process*, not the command.

**Safe test.**

```powershell
net view
# Expect: Sysmon 1 for net.exe with CommandLine `net  view`,
#         ParentImage = your interactive shell.
# The rule keys on the parent context, not the command: run it from a signed
# management agent and it should stay quiet, which is the tuning you will do.

net use
arp -a
# Expect: Sysmon 1 for each; arp.exe is the quieter neighbour-enumeration
#         equivalent, and is worth adding to your own rule set.
```

**Safe test — shared with T1592.002.** The same commands produce both
techniques' telemetry, and the rules differ only in which fields they read.

---

### T1027.002 — PyInstaller packaging

**What it is.** `pyinstaller --onefile` bundles a Python program and its
interpreter into one executable. At run time it extracts itself to
`%TEMP%\_MEI<random>` and runs from there. Nothing about that is malicious — it
is how a great many legitimate tools ship — which makes it a *poor* signal on its
own and a *useful* one in combination.

**Why three rules.** `pyinstaller_onefile_execution.yml` matches a process whose
image path contains `_MEI`; `mei_extraction_dir.yml` matches the directory being
created; `dropper_unsigned_temp_exec.yml` adds the signature predicate. The
combination — MEI extraction, unsigned, from a temp path, followed by network
activity — is the shape; any single one is noise.

**Safe test** — build a benign one-file executable and run it:

```powershell
pip install pyinstaller
Set-Content "$env:TEMP\hello.py" 'print("lab canary"); input("enter to exit")'
pyinstaller --onefile "$env:TEMP\hello.py" --distpath "$env:TEMP\dist"
& "$env:TEMP\dist\hello.exe"
# Expect: Sysmon 11 for _MEI<id> directory creation, Sysmon 1 for hello.exe,
#         then Sysmon 1 for the extracted python child from _MEI.
```

This is the cleanest way to exercise these three rules, and it produces every
event they read.

```powershell
Remove-Item -Recurse -Force "$env:TEMP\dist","$env:TEMP\build","$env:TEMP\hello.py","$env:TEMP\hello.spec" -ErrorAction SilentlyContinue
```

---

### T1070.004 — Self-deletion

**What it is.** A binary removes itself from disk after running. Windows will not
let a running image delete its own file, so the usual pattern is to spawn a
command that waits and then deletes — `cmd /c ping -n 3 127.0.0.1 & del <self>`.

**Why the telemetry is a process tree.** `self_delete.yml` matches `cmd.exe` with
a `CommandLine` containing a delete of a path, spawned by a process whose image is
that same path. The `ping` is a sleep; the `&` is the sequencing.

**Safe test.**

```powershell
Copy-Item C:\Windows\System32\notepad.exe "$env:TEMP\labself.exe"
& "$env:TEMP\labself.exe"
# From the same user session:
cmd /c "ping -n 3 127.0.0.1 > nul & del `"$env:TEMP\labself.exe`""
# Expect: Sysmon 1 for cmd.exe with ParentImage = labself.exe and a del CommandLine
```

**Cleanup.** There is nothing to undo — `del` removed `labself.exe`, and that
deletion *is* the behaviour under test. Confirm it is gone:

```powershell
Test-Path "$env:TEMP\labself.exe"   # expect False
```

---

### T1592.002 — Host and network reconnaissance

**What it is.** Before acting, establish where you are: `systeminfo`, `net view`,
`nltest /dclist`, `ipconfig`, and the cloud-metadata equivalent of "what is my
public IP". Each is a signed Windows binary or a plain HTTP GET.

**Why the rules are low-severity.** These commands run in every IT department
constantly. `net_view_recon.yml` and `wmi_recon_command.yml` match them with the
parent-process context that makes them odd (a user session that has done nothing
else, or a parent that is an Office process); `ipify_egress.yml` matches a DNS
lookup or connection to a "what is my IP" service.

**Safe test.**

```powershell
net view
nltest /dclist:   # if the RSAT tools are present
Get-CimInstance Win32_ComputerSystem | Select-Object Domain, TotalPhysicalMemory
nslookup myip.opendns.com resolver1.opendns.com
# Expect: Sysmon 1 for each, Sysmon 22 for the DNS, and the recon rules to fire
#         only if the parent context matches.
```

**Why they will probably not fire.** With `ParentImage = powershell.exe` these
look exactly like administration, which is what they are. The rules are for the
*context* — that is the design, and it means these are the rules most likely to
need tuning on your estate.

---

## Rule index by technique

Generated from the rules, so it cannot drift from what they cite.
Each link is the lab procedure above for that technique.

| Technique | Rules that cite it |
|---|---|
| [T1005](#t1005-data-from-local-system-browser-stores) | `credential_file_access.yml` |
| [T1027.002](#t1027002-pyinstaller-packaging) | `dropper_unsigned_temp_exec.yml`, `mei_extraction_dir.yml`, `pyinstaller_onefile_execution.yml` |
| [T1053.005](#t1053005-scheduled-tasks) | `python_parent_child_shape.yml`, `runkey_schtask_startup_persistence.yml`, `schtask_onlogon.yml` |
| [T1056.001](#t1056001-keylogging-by-polling) | `keylog_encrypted_file.yml` |
| [T1059](#t1059-interpreter-and-script-host-child-processes) | `python_parent_child_shape.yml` |
| [T1070.004](#t1070004-self-deletion) | `self_delete.yml` |
| [T1071.001](#t1071001-http-beaconing-with-custom-headers) | `beacon_custom_headers.yml`, `beacon_interval_shift.yml`, `beaconing_frequency.yml`, `campaign_implant_sequence.yml`, `host_selfsigned_tls.yml`, `ua_anomaly.yml` |
| [T1091](#t1091-removable-media-spreading) | `autorun_inf_writes.yml`, `removable_media_spreader_write.yml` |
| [T1105](#t1105-ingress-tool-transfer) | `dropper_unsigned_temp_exec.yml`, `removable_media_spreader_write.yml`, `self_update_rewrite.yml` |
| [T1113](#t1113-screen-capture) | `screenshot_bmp_artifact.yml` |
| [T1135](#t1135-network-share-and-domain-enumeration) | `net_view_recon.yml` |
| [T1497](#t1497-virtualisation-and-sandbox-checks) | `campaign_implant_sequence.yml`, `cpu_info_read.yml`, `patch_sequence.yml` |
| [T1546.003](#t1546003-wmi-event-subscription) | `campaign_implant_sequence.yml`, `wmi_binding_create.yml`, `wmi_consumer_create.yml`, `wmi_event_subscription_persistence.yml`, `wmi_filter_create.yml`, `wmi_subscription_triple.yml` |
| [T1547.001](#t1547001-registry-run-keys-and-startup-folder) | `autorun_inf_writes.yml`, `mutex_single_instance.yml`, `run_key_write.yml`, `runkey_schtask_startup_persistence.yml`, `startup_folder_cmd.yml` |
| [T1555.003](#t1555003-files-a-browser-stores-credentials-in) | `credential_file_access.yml`, `sqlite_temp_copy.yml` |
| [T1568.002](#t1568002-dga-hostnames) | `dga_high_entropy_dns.yml`, `dns_query_burst_host.yml`, `dns_random_label_query.yml`, `nxdomain_long_label.yml` |
| [T1592.002](#t1592002-host-and-network-reconnaissance) | `ipify_egress.yml`, `net_view_recon.yml`, `wmi_recon_command.yml` |
| [T1685](#t1685-amsi-and-etw-tampering) | `amsi_etw_patch.yml`, `campaign_implant_sequence.yml`, `patch_sequence.yml`, `security_component_tamper.yml` |

## What this page closes, and what it cannot

**Closes** the "nobody knows what to run" half of G-01: each technique now has a
mechanism, an expected event ID, and a safe experiment with the cleanup command.

**Cannot close** the rest of G-01, G-02, G-03, G-04, G-05, G-09, G-11, G-17,
G-21, G-22, G-24, G-25, G-26 — they need a real host, a real proxy, real
benign traffic, or a sample. Running this page produces the raw material for
those; it does not substitute for them.

**Two things to record as you go**, both in `tuning/observations.csv`:
what you expected, and what you got. A test that produces *nothing* is the most
valuable result on this page, because it means the telemetry pipeline is wrong
and every rule is quietly blind.

## The line this page does not cross

This is a **detection** repository. It explains mechanisms so that detections can
be reasoned about and tested. It does not contain, and will not be extended to
contain, working implementations: no patching code that actually defeats AMSI, no
credential decryptor, no keylogger that captures a keystroke, no loader that
executes a payload. Where a test would need one of those, the page says so and
stops — G-05, G-09 and G-17 exist to record exactly that, rather than to paper
over it.
