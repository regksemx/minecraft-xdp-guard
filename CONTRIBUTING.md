# Contributing

Bug reports, questions and pull requests are welcome.

## Issues

- **A bug**: the version (`xdp-loader -V`), the kernel (`uname -r`), the
  output of `sudo xdp-loader doctor`, and what you expected to happen. If a
  player can not join, say which client (Java, Bedrock RakNet, NetherNet,
  Voice Chat) and whether it works with `systemctl stop minecraft-xdp`.
- **A question or an idea**: open a discussion instead.
- **A security problem**: not in public, see [SECURITY.md](SECURITY.md).

## Pull requests

Everything builds and runs in a Linux container, macOS included:

```bash
dev/run.sh                                                           # all tests
dev/run.sh bash -c 'cargo fmt --check && cargo clippy --release -- -D warnings'
```

- New packet handling in `xdp/` comes with checks in `dev/kernel-test.sh`
  (and in the native C tests when it touches a parser). The program has to
  pass the kernel verifier: `xdp-loader --check` on a real kernel is the
  final word, older kernels are stricter about complexity.
- A change to the loader's behaviour comes with a test in `cargo test` or
  `dev/e2e-test.sh`.
- A new option is documented in `docs/configuration.md`.
- One commit message line in the conventional style: `fix: …`, `feat: …`,
  `docs: …`.

By contributing you agree that your work is licensed like the project:
BSD-3-Clause, and GPL-2.0 OR BSD-3-Clause for the program in `xdp/`.
