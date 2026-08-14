# Disclosure policy

This policy is written before the project has produced a single finding, deliberately. A disclosure
policy invented after you already have something to publish is a rationalisation.

## What we publish

**Observations, not conclusions about intent.**

We publish statements of the form *"version X of package Y sent value V to host H when tool T was
invoked with inputs we supplied, and V appears in neither the tool's declared schema nor our
inputs — here is the recorded request."*

We do not publish statements of the form *"package Y is malicious"* or *"the maintainer of Y is
stealing data"*. Not because we are timid, but because the first kind of statement is a fact we can
evidence and the second is a claim about a person's state of mind that we cannot. "Cannot conclude"
is also the strongest legal position available to us; "they lied" is litigable.

## Before publishing anything adverse about a named package

1. **Notify the maintainer first**, using the contact in the package metadata, the repository
   `SECURITY.md`, or the registry's abuse channel — in that order.
2. **Wait 90 days**, or until a fix ships, whichever comes first.
3. **Shorten the window only when the package is already publicly known to be malicious** (for
   example, it already carries an OSV malware advisory), or when the registry has already removed
   it. In those cases the information is public and delay protects nobody.
4. **Extend the window on request** where the maintainer is engaging in good faith. We would rather
   be late than wrong.
5. **Send the maintainer the full recorded evidence**, not a summary. If our finding is wrong, they
   are the people best placed to show us how, and we want that to be easy.

If we get no response, we say we got no response — and we distinguish that from "they refused to
comment", which is a different fact.

## Corrections

If a published finding turns out to be wrong, the correction goes in the same place as the finding,
with equal prominence, and the original stays visible with the correction attached. We do not
quietly delete.

## Reporting a problem in mcpgap itself

See [SECURITY.md](SECURITY.md).

## What we will not do

- Probe, scan, or interact with systems we do not own. We install packages and run them locally.
  That is the entire method, and keeping it that way is what keeps this clear of the
  computer-misuse statutes that have been used against researchers with less careful designs.
- Publish an aggregate from an incomplete sample without saying the sample is incomplete.
- Publish a rate whose denominator includes tools we failed to exercise.
- Take a financial position in anything we scan, before or after publication.
