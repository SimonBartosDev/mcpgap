# mcpgap

Runs an MCP server and records what it actually does, then compares that to what it declares —
and to what the previous version did.

**Status: both acceptance gates pass.** mcpgap detects the `postmark-mcp` rug pull end to end —
installing both versions, running them under a sandbox, and diffing what they actually sent — and
detects undeclared filesystem writes and subprocess spawns against a synthetic fixture. It has been
run against one real package. Treat it as a demonstration that the method works, not as a tool you
can point at your dependencies.

Known gaps, all deliberate: macOS only (the sandbox is seatbelt; there is no Linux backend yet) and
no CLI beyond `--version`.

## What this is for

Every MCP scanner in wide use — Cisco `mcp-scanner`, Snyk `agent-scan`, Docker MCP Gateway,
Promptfoo — analyses *declared* metadata: tool descriptions, config, static code. The official MCP
registry verifies namespace (who published it), not behaviour. All of that is useful, and mcpgap is
not a competitor to any of it.

The gap is that nobody runs the server and watches it. mcpgap installs an MCP server in a sandbox,
calls its tools with tagged inputs, records the outbound requests, and reports the difference
between two versions.

## The case it is built around

`postmark-mcp` v1.0.16, disclosed 25 September 2025 by Koi Security — the first publicly documented
malicious MCP server. Fifteen releases of genuine development, then one added line:

```js
Bcc: 'phan@giftshop.club',
```

inside the `sendEmail` tool. It BCC'd every outgoing email — password resets, invoices — to the
author. ~1,500 weekly downloads, ~300 organisations.

**Why this case is the right gate:** the added BCC opens no new connection. Same host, same
endpoint, same request count, same TLS SNI. The exfiltration rides inside the body of a request the
tool was always supposed to make, and the mail is delivered by Postmark's own infrastructure — a
victim host never contacts `giftshop.club` at all. Any scanner watching hosts, DNS, or connection
counts is structurally blind to it. That is the point mcpgap exists to make, so the acceptance test
asserts *both* that we surface the BCC *and* that the host-level view stays silent.

## What it cannot tell you

This section is not boilerplate. It is the reason to trust the rest.

- **A tool we could not exercise is `cannot_conclude`, never "clean".** Silence is not a pass. If we
  could not call a tool, it is excluded from any rate we publish rather than counted against the
  package — counting our own ignorance as the package's fault inflates the accusation.
- **Install-time behaviour is observed, but only the hooks npm would really run.** Dependencies are
  downloaded with `--ignore-scripts`, then lifecycle hooks are executed *inside the sandbox* and
  recorded. Only the hooks npm actually runs are executed: `preinstall`, `install` and `postinstall`
  for dependencies, plus `prepare` for the root package. A dependency's `prepare` is deliberately
  skipped — npm does not run it for a registry install, and running it would report commands as
  package behaviour that no real install would ever execute.
- **Filesystem writes are observed completely; reads and subprocesses are not.** Writes are found by
  hashing the sandbox's writable tree before and after each tool call. That is complete rather than
  best-effort for a specific reason: the sandbox refuses writes anywhere else, so a write that
  happened is a write we saw, and there is nothing for the package to opt out of. Reads and
  subprocess spawns come from a preload shim inside the process, which the code under test can
  unhook or bypass through a native addon. Those findings are labelled `[best-effort]`, and **the
  absence of one is not evidence that nothing happened.**
- **We report observations, not intent.** "This tool sent a value to a host that was in neither your
  input nor its manifest, here is the request" is a fact. "This package is malicious" is a
  conclusion we do not need to state and will not.
- **One run is not a measurement.** Verdicts require agreement across repeated runs. Runs that
  disagree are reported as `unstable`, not resolved by picking one.
- **Sealed by default.** The sandbox never reaches the real upstream API; the proxy answers with
  canned responses. So we observe what the server *tried* to send, not what a real API would have
  done in reply. A server that changes behaviour based on real responses can hide from us.
- **We only see what crosses the boundary we watch.** Behaviour triggered by conditions we did not
  create — a date, a specific input, a response we did not fake — is not observed, and "not
  observed" is reported as exactly that.

## Ethics

We run servers we installed, in our own sandbox, on our own machine. We do not probe anyone else's
systems. Maintainers are notified before any adverse finding about a named package is published;
see [DISCLOSURE.md](DISCLOSURE.md). We take no financial position in anything we scan.

## Licence

Apache-2.0.
