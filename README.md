# nested-musig2

Implementation related to the paper:

**Nested MuSig2**
https://eprint.iacr.org/2026/223.pdf

---

## Overview

`nested-musig2` provides an experimental Rust implementation and research environment for Nested MuSig2 constructions.

**Status:** Research / Experimental  
This library is under active development and **has not been externally audited**.

Do **NOT** use in production systems handling real funds or critical assets without independent security review.

---

## Features

- Nested MuSig2 protocol experimentation
- Modular cryptographic components
- Designed to integrate with `crypto-rs`
- Deterministic builds via Cargo

---

## Installation

Clone repositories side-by-side:

```
projects/
├── crypto-rs/
└── nested-musig2/
```

```bash
git clone https://github.com/BEULAHEVANJALIN/crypto-rs
git clone https://github.com/BEULAHEVANJALIN/nested-musig2
cd nested-musig2
```

---

## Dependency Model

This project depends on **crypto-rs**.

### Development Mode (default)

`.cargo/config.toml` replaces the Git dependency with a local path:

```toml
[patch."https://github.com/BEULAHEVANJALIN/crypto-rs"]
crypto-rs = { path = "../crypto-rs" }
```

This enables:

* fast iteration
* simultaneous development
* workspace-style workflow

### Remote / CI Mode

If `.cargo/config.toml` is removed, Cargo automatically fetches:

```
https://github.com/BEULAHEVANJALIN/crypto-rs
```

No configuration changes required.

---

## License