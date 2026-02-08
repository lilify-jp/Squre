# SQURE

**S**ecure **Q**uality **U**ncrackable **R**untime **E**ncryption - Advanced Binary Protection Toolkit for Windows PE files.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

## Features

SQURE provides multi-layered protection against reverse engineering, debugging, and tampering:

| Feature | Description |
|---------|-------------|
| **Nanomite** | Replaces conditional branches with INT3, dispatched by VEH at runtime |
| **XTEA Encryption** | Per-page .text encryption with key derivation from PE headers |
| **VM Protection** | Virtualizes code into custom bytecode interpreter |
| **Tidal Memory** | Page-granular encryption with on-demand VEH decryption |
| **Honeypot** | Decoy functions and trap code to mislead analysis |
| **Anti-Debug** | PEB.BeingDebugged detection with key poisoning |
| **Anti-Dump** | Memory dump prevention techniques |
| **Sandbox Detection** | CPUID-based VM/hypervisor detection |
| **Import Obfuscation** | IAT hashing with runtime resolution |
| **Integrity Checking** | Cascade hash chain for tamper detection |
| **Shamir Secret Sharing** | Key split across 3 shares in GF(2^64) |
| **White-box Crypto** | Lookup tables resistant to DCA attacks |

## Installation

```bash
# Clone the repository
git clone https://github.com/mttm2/squre.git
cd squre

# Build release binary
cargo build --release

# The CLI is at target/release/squre-cli.exe
```

## Quick Start

```bash
# Basic protection
squre-cli protect app.exe -o protected.exe

# Maximum protection (all features enabled)
squre-cli protect app.exe -o protected.exe --level maximum

# Custom seed for reproducible builds
squre-cli protect app.exe -o protected.exe -s 0xDEADBEEF
```

## CLI Options

```
squre-cli protect [OPTIONS] --output <OUTPUT> <INPUT>

Options:
  -o, --output <OUTPUT>     Output PE file path
  -s, --seed <SEED>         CEWE seed (hex, random if not specified)
  -l, --level <LEVEL>       Protection level: standard (default) or maximum

Protection Features:
  --vm                      Enable VM protection (virtualized code)
  --honeypot                Enable honeypot mode (decoy functions, traps)
  --tidal                   Enable Tidal Memory (page-granular encryption)
  --ultra                   Enable ultra-hardened mode (16 anti-analysis phases)
  --harden                  Enable hardened mode (polymorphic sections)
  --anti-dump               Enable anti-memory-dump protection
  --integrity-check         Enable code integrity checking
  --direct-syscall          Enable direct syscalls (bypass user-mode hooks)

Tuning:
  --junk-level <0-3>        Junk code insertion level
  --fake-keys <N>           Number of decoy keys to embed
  --layers <1-3>            Encryption layers (XTEA/XOR/Rolling)
  --obfuscate <0-3>         Obfuscation level
  --no-nanomite             Disable nanomite branches
  --no-anti-debug           Disable anti-debug checks
```

## Protection Levels

### Standard (default)
- Nanomite branch obfuscation
- XTEA .text encryption
- Anti-debug with key poisoning
- Import obfuscation
- Basic junk code

### Maximum (`--level maximum`)
- All standard features
- VM protection
- Tidal Memory
- Honeypot traps
- Ultra-hardened anti-analysis (16 phases)
- Sandbox/VM detection
- Direct syscalls
- Maximum junk code and obfuscation

## For Rust Projects

SQURE can automatically protect Rust binaries with source-level integration:

```bash
# Build and protect a Rust project
squre-cli build ./my-rust-project -o protected.exe --level maximum
```

Add the `squre-core` crate to enable macro-based protection:

```rust
use squre_core::anti_debug;

fn main() {
    // Install anti-debug and nanomite handler
    anti_debug!();

    // Your code here
}
```

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                    Protection Flow                          │
├─────────────────────────────────────────────────────────────┤
│  1. OS loads PE → entry = .sqpre (obfuscated stub)          │
│  2. .sqpre decrypts .sqinit using PE-derived XOR key        │
│  3. .sqinit decrypts .text using XTEA with page keys        │
│  4. Jump to original entry point (CRT init → main)          │
│  5. anti_debug!() installs VEH + loads nanomite table       │
│  6. INT3 branches dispatched by VEH handler                 │
│  7. Tidal Memory encrypts pages → VEH decrypts on demand    │
└─────────────────────────────────────────────────────────────┘
```

## Architecture

```
squre/
├── crates/
│   ├── squre-cli/          # CLI tool for binary protection
│   │   ├── src/
│   │   │   ├── main.rs     # CLI entry point
│   │   │   ├── pe/         # PE parsing and writing
│   │   │   └── transform/  # Protection transforms
│   │   │       ├── hardening.rs      # Anti-analysis phases
│   │   │       ├── honeypot.rs       # Decoy code generation
│   │   │       ├── vm_protect.rs     # VM bytecode compiler
│   │   │       └── ...
│   └── squre-core/         # Runtime macros for Rust integration
├── examples/               # Example projects
└── TUTORIAL.md            # Detailed usage guide
```

## Security Considerations

SQURE is designed for **legitimate software protection**:
- Protect commercial software from piracy
- Prevent reverse engineering of proprietary algorithms
- Add tamper detection to security-critical applications

**Do not use for malware.** This tool is for defensive purposes only.

## Performance

Protected binaries have minimal runtime overhead:
- Startup: ~10-50ms for decryption (depends on binary size)
- Runtime: Nanomite dispatch adds ~1μs per branch
- Memory: +50-200KB for protection sections

## Limitations

- Windows PE (x64) only
- Requires Rust 1.70+
- Some features may trigger antivirus false positives
- Debug builds are not recommended for protection

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing`)
5. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- Inspired by commercial protectors (VMProtect, Themida)
- Built with Rust for memory safety and performance
- Uses XTEA for lightweight encryption

---

**SQURE** - Because your code deserves protection.
