## Summary

<!-- What changes, and why is this the smallest useful change? -->

## Security impact

<!-- Explain any effect on secret visibility, destination authority, or child isolation. -->

## Verification

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo test --all-targets --locked`
- [ ] `cargo clippy --all-targets --all-features --locked -- -D warnings`
- [ ] No real credential, private URL, or personal data appears in tests or output
- [ ] Documentation and `CHANGELOG.md` are updated when behavior changes

## Scope

- [ ] The change protects project credentials rather than the agent's own login
- [ ] New behavior fails closed and has a regression test
