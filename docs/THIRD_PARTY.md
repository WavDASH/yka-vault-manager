# Third-party components

YKA source is GPL-3.0-only; see `LICENSE`. No SiriKali application source was copied. Qt libraries are dynamically loaded; source and dependency locks are provided for rebuilding. WebEngine is not used.

| Component | Version | Source and license |
| --- | --- | --- |
| SecureFS | 2.0.0 Windows amd64 | [Release](https://github.com/netheril96/securefs/releases/tag/v2.0.0); MIT |
| WinFsp | Installed separately | [Source](https://github.com/winfsp/winfsp); GPLv3 with FLOSS exception. The installer bundles the signed WinFsp 2.1.25156 MSI for computers without WinFsp; existing installations are retained. |
| Rust age | 0.11.1 | [rage](https://github.com/str4d/rage); MIT or Apache-2.0 |
| age-plugin-yubikey | 0.5.1, commit `9329e31dd3d0819d5d7b739aef59e455e10fcfa1` | [Source](https://github.com/str4d/age-plugin-yubikey); MIT or Apache-2.0, with restricted-operation patch |
| PySide6 / Qt | 6.10.2 | [Licensing](https://doc.qt.io/qt-6/licensing.html); applicable open-source terms |
| YubiKey Manager / yubikit | 5.9.2 | [Source](https://github.com/Yubico/yubikey-manager); included license texts |
| cryptography | 50.0.2 | [Source](https://github.com/pyca/cryptography); Apache-2.0 or BSD-3-Clause |
| Python | 3.13.16 | [Source](https://www.python.org/downloads/release/python-31316/); PSF license |

Other versions and notices are in `requirements.lock.txt`, `Cargo.lock`, `docs/dependency-inventory.json`, and `docs/licenses/`. The inventory includes development and cross-target dependencies; it is not a final binary SBOM.

Official download URLs and SHA-256 values are recorded in `vendor/dependencies.json`. The application does not download executables at runtime.

The patched age plugin source and dependency lock are included in the matching source distribution and rebuilt by its normal build script. The patch disables generation, overwrite, no-argument interactive setup, and killing other agents. It also forwards touch/cryptographic-operation status via the age callback immediately around the private-key operation. It does not change cryptographic protocols. Hardware compatibility remains subject to acceptance tests.

Qt sources: [Qt](https://code.qt.io/cgit/qt/), [PySide](https://code.qt.io/cgit/pyside/pyside-setup.git/). Use matching versions when rebuilding or replacing libraries.

YKA executables and the Inno Setup installer are unsigned; clean-machine acceptance and a final release SBOM remain pending.

WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos. [WinFsp repository](https://github.com/winfsp/winfsp).
