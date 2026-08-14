# Security

## This repository contains live malware

`fixtures/` holds real, unmodified malicious package code, kept as acceptance-test material —
currently `postmark-mcp` v1.0.16 (OSV [`MAL-2025-47604`](https://osv.dev/vulnerability/MAL-2025-47604)).

Fixtures are stored as **password-protected zip archives, password `infected`**, following the
convention used by public malware corpora such as Datadog's
`malicious-software-packages-dataset`. This is not security through obscurity — the password is
right here. It exists so that the files cannot be executed by accident, cannot be unpacked by a
stray glob, and do not trip other people's scanners while sitting in your working tree.

**Do not unpack a fixture by hand.** The loader will only extract into a run-scoped working
directory that it creates itself and that is git-ignored; it rejects absolute paths, parent-directory
traversal, symlinks and non-regular members in the archive, and it refuses to write into the
repository. That is a narrower guarantee than "it cannot be unpacked outside the sandbox" — nothing
stops you running `unzip` yourself — so treat the archives as what they are.

## Reporting a vulnerability in mcpgap

Open a GitHub security advisory on this repository, or email the address on the maintainer's
profile. Please include what you ran and what you observed. We will confirm receipt within 7 days.

Findings in mcpgap's *sandbox containment* are the highest severity we recognise: this tool runs
hostile code on purpose, and a containment escape is the failure that matters most. If you find one,
say so prominently and we will treat it accordingly.

## Threat model

mcpgap executes untrusted third-party code by design. Its safety rests on the platform sandbox, not
on the good behaviour of the code under test.

**The preload shim is not a security boundary.** `src/mcpgap/observers/shim.cjs` is injected into the
package's own process to record filesystem reads and subprocess spawns. It is an observation aid and
nothing more: code under test can unhook it, keep a reference captured before it patched, or reach
the kernel through a native addon. It is not relied on for containment, and no finding it fails to
produce is treated as evidence of absence. Filesystem *writes* are established independently by
hashing the sandbox's writable tree, which the package cannot evade — the sandbox refuses writes
anywhere else.

**What the sandbox is asserted to prevent**, with a regression test for each:

- reading anything under `/Users` or `/Volumes` — the whole user namespace, which covers
  `~/.ssh`, `~/.aws`, `~/.npmrc`, `~/.config/gh` and any credential location invented later
- writing anywhere outside the per-run working directory
- reaching any network host by name
- reaching any network host by raw IP, bypassing DNS
- inheriting the parent's environment, including credential-shaped variables

Every rule above has a test that asserts the *denial*. A containment rule with no test asserting it
denies is not containment — during development two rules silently failed to match their intended
paths, and only a test that checked the denial would have caught it.

**What the sandbox does not prevent, and we do not claim it does:**

- **Reading system files.** Reads outside `/Users` and `/Volumes` are allowed. This is weaker than
  the narrow read allowlist originally intended: Node aborts on startup without broad system reads,
  and the abort is silent — no stderr, no sandbox log — so the minimal read set could not be
  established empirically. Rather than ship a profile whose description was tighter than its
  behaviour, the profile denies the user namespace wholesale and says so here.
- **User data stored outside `/Users` and `/Volumes`.** If your documents live somewhere else, they
  are readable by the code under test.
- Local resource exhaustion. There are no CPU or memory limits yet.
- Kernel-level escapes from macOS seatbelt. This is a sandbox, not a virtual machine. On a machine
  holding data you cannot afford to lose, run mcpgap in a disposable VM.
- Anything at all during dependency installation, which happens *outside* the sandbox with
  `--ignore-scripts`. That flag stops lifecycle scripts from running; it is not a sandbox.

## Supply chain of mcpgap itself

Dependencies are hash-pinned in `uv.lock`. CI runs `pip-audit`, `bandit`, CodeQL, `gitleaks`, and
emits a CycloneDX SBOM on every build; all of them are blocking. The runtime dependency list is one
package, on purpose.
