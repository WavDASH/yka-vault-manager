# YKA restricted plugin build

Based on age-plugin-yubikey 0.5.1, upstream commit `9329e31dd3d0819d5d7b739aef59e455e10fcfa1`.

YKA integration changes (2026-10-16 source distribution): no-argument interactive provisioning and generate/force operations are disabled; smart-card agent termination is disabled; callbacks report touch and cryptographic-operation progress around the private-key operation. The age wire format and cryptography are unchanged.

The matching three-file patch is `../age-plugin-yubikey.patch`. The included sources already contain it; do not apply it again. Build from the repository root with the documented Rust toolchain. Upstream's developer tests, CI, examples and historical documentation are omitted from this clean source copy. MIT and Apache-2.0 notices are preserved.
