# Security policy

The filter runs as root and inside the kernel, so security reports get
priority over everything else here.

## Reporting a vulnerability

Report privately through GitHub:
**[Security → Report a vulnerability](../../security/advisories/new)**.
Please do not open a public issue for it.

Useful to include: the version (`xdp-loader -V`), the kernel (`uname -r`), the
XDP mode, the relevant part of `config.toml`, and packets or steps that show
the problem (a pcap or a script is ideal).

You get an answer within a few days. A fix ships as a new release, and the
advisory is published after it, with credit unless you prefer otherwise.

What counts, for example:

- a packet or sequence of packets that crashes or wedges the loader, or makes
  the filter pass traffic it is configured to drop;
- a way to make the filter drop legitimate players at a cost far below the
  flood it is meant to stop;
- anything that lets an unprivileged local user change the filter, its pinned
  tables or its configuration;
- the installer or the release process installing something other than what
  was built from this repository.

Out of scope: attacks that saturate the uplink before packets reach the
machine (no on-host filter can stop those), and bots that complete real
connections from real addresses (see the FAQ in the README).

## Supported versions

Only the latest release gets fixes. Upgrading keeps the config and every
connection: run the installer again.

## Verifying a release

Every release since v1.0.4 carries a build provenance attestation: proof that
GitHub Actions built the files from this repository at the tagged commit.

```bash
gh attestation verify xdp-loader --repo regksemx/minecraft-xdp-guard
sha256sum -c SHA256SUMS --ignore-missing
```

The installer does both by itself: the checksum always, the attestation when
an authenticated `gh` is installed on the machine.
