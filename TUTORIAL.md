# SQURE Tutorial - Complete Guide

## Overview

SQURE (**S**ecure **Q**uality **U**ncrackable **R**untime **E**ncryption) is an open-source binary protection toolkit for Windows PE files. It provides multi-layered protection against reverse engineering, debugging, and memory dumping.

## Installation

```bash
# Clone the repository
git clone https://github.com/mttm2/squre.git
cd squre

# Build from source
cargo build --release -p squre-cli

# The CLI will be at:
# target/release/squre-cli.exe
```

---

## Quick Start

### Method 1: Protect Command

Protect an existing binary:

```bash
squre-cli protect input.exe -o protected.exe
```

### Method 2: Build Command (Rust Projects)

Compile and protect a Rust project in one step:

```bash
squre-cli build my_project/ -o protected.exe
```

---

## CLI Commands

### 1. `protect` - Binary Post-Processing

Apply protection to an existing PE binary.

```bash
squre-cli protect <INPUT> -o <OUTPUT> [OPTIONS]
```

**Example:**
```bash
squre-cli protect my_app.exe -o protected.exe --level maximum
```

### 2. `build` - Full Protection Pipeline

Compiles a Rust project with SQURE macros and applies binary protection.

```bash
squre-cli build <INPUT_DIR> -o <OUTPUT> [OPTIONS]
```

**Example:**
```bash
squre-cli build examples/basic -o protected.exe --level maximum
```

### 3. `analyze` - PE Analysis

Analyze PE structure of a binary.

```bash
squre-cli analyze <INPUT>
```

### 4. `strings` - String Extraction

Extract readable strings from binary.

```bash
squre-cli strings <INPUT> [--min-len N]
```

### 5. `info` - Protection Info

Show SQURE protection metadata from a protected binary.

```bash
squre-cli info <INPUT>
```

---

## Protection Levels

| Level | Description |
|-------|-------------|
| `standard` | Default preset (junk=1, fake_keys=3, layers=1) |
| `maximum` | Full protection (all features enabled) |

**Example:**
```bash
squre-cli protect app.exe -o out.exe --level maximum
```

---

## Protection Features

### Nanomite Branch Obfuscation

Replaces conditional jumps with INT3 breakpoints, dispatched by VEH at runtime.

```bash
# Enabled by default
squre-cli protect app.exe -o out.exe

# Disable nanomites
squre-cli protect app.exe -o out.exe --no-nanomite
```

### VM Protection

Converts code to custom VM bytecode with randomized opcodes.

```bash
squre-cli protect app.exe -o out.exe --vm
```

### Tidal Memory

Page-granular encryption with VEH decryption and background re-encryption.

**How it works:**
1. Each 4KB page of `.text` is XOR-encrypted with a unique derived key
2. All pages are marked `PAGE_NOACCESS`
3. VEH handler catches ACCESS_VIOLATION -> decrypts page -> `PAGE_EXECUTE_READ`
4. Background tide thread re-encrypts cold pages every 50ms
5. At any instant, <0.1% of code is in plaintext

**Anti-dump effect:** Memory dumps capture almost entirely encrypted code.

```bash
squre-cli protect app.exe -o out.exe --tidal
```

### Honeypot Mode

Adds decoy functions, trap code, and misleading strings.

```bash
squre-cli protect app.exe -o out.exe --honeypot
```

### Hardened Mode

Enables full anti-analysis suite:
- Polymorphic section names
- 9 anti-debug checks
- RDTSC timing checks
- Multi-path entry
- Sandbox detection (CPUID/hypervisor bit/environment)

```bash
squre-cli protect app.exe -o out.exe --harden
```

### Ultra-Hardened Mode

Enables all 16 anti-analysis phases (implies --harden).

```bash
squre-cli protect app.exe -o out.exe --ultra
```

### Anti-Memory-Dump

Protects against memory dumping with PAGE_GUARD and auto re-encryption.

```bash
squre-cli protect app.exe -o out.exe --anti-dump
```

### Direct Syscall

Bypasses user-mode API hooks by making direct `syscall` instructions.

```bash
squre-cli protect app.exe -o out.exe --direct-syscall
```

### Encryption Layers

```bash
# Layer 1: XTEA only (default)
squre-cli protect app.exe -o out.exe --layers 1

# Layer 2: XTEA + XOR stream
squre-cli protect app.exe -o out.exe --layers 2

# Layer 3: XTEA + XOR + Rolling cipher
squre-cli protect app.exe -o out.exe --layers 3
```

### Obfuscation Level

```bash
# 0 = none, 1 = basic (default), 2 = medium, 3 = full
squre-cli protect app.exe -o out.exe --obfuscate 3
```

---

## Full Options Reference

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
  --process-guard           Enable Process Guard (3-process Shamir key split)

Tuning:
  --junk-level <0-3>        Junk code insertion level
  --fake-keys <N>           Number of decoy keys to embed
  --layers <1-3>            Encryption layers (XTEA/XOR/Rolling)
  --obfuscate <0-3>         Obfuscation level
  --no-nanomite             Disable nanomite branches
  --no-anti-debug           Disable anti-debug checks
  --no-polymorphic          Disable polymorphic stubs
  --no-encrypt-stub         Disable stub encryption
  --no-distributed-key      Disable distributed key embedding
```

---

## Examples

### Basic Protection

```bash
squre-cli protect my_app.exe -o protected.exe
```

### Maximum Protection (Recommended)

```bash
squre-cli protect my_app.exe -o protected.exe --level maximum
```

This enables all features:
- VM protection
- Tidal Memory
- Honeypot
- Ultra-hardened anti-analysis
- Sandbox detection
- Direct syscalls
- Maximum obfuscation

### Full Runtime Protection (3-Way Combo)

Combines VM, Tidal Memory, and Honeypot:

```bash
squre-cli protect my_app.exe -o protected.exe --honeypot --vm --tidal
```

### Custom Seed (Reproducible Builds)

```bash
squre-cli protect my_app.exe -o protected.exe --seed 0xDEADBEEF
```

### Debugging Build

```bash
squre-cli protect my_app.exe -o debug.exe --no-anti-debug
```

---

## Rust Integration

For Rust projects, use the `squre-core` crate:

```rust
use squre_core::anti_debug;

fn main() {
    // Install anti-debug and nanomite handler
    anti_debug!();

    println!("Protected application running!");
}
```

Build with full protection:

```bash
squre-cli build my_rust_project/ -o protected.exe --level maximum
```

---

## Section Layout

Protected binaries contain these SQURE sections:

| Section | Purpose |
|---------|---------|
| `.sqpre` | First-stage decryption stub (PE-derived key) |
| `.sqinit` | Second-stage XTEA decryption stub |
| `.sqrun` | Runtime initialization (VEH, nanomite table) |
| `.sqtdl` | Tidal Memory (when --tidal enabled) |
| `.sqvm` | VM bytecode (when --vm enabled) |
| `.sqimp` | Import resolver stub |
| `.squre` | Metadata: nanomite table, white-box tables, cascade chain |
| `.valid8` | Honeypot decoy functions (when --honeypot enabled) |

**Section count examples:**
- Basic protection: 5 -> 10 sections
- `--level maximum`: 5 -> 12 sections
- `--honeypot --vm --tidal`: 5 -> 13 sections

---

## How It Works

```
1. OS loads PE -> entry = .sqpre (obfuscated stub)
2. .sqpre decrypts .sqinit using PE-derived XOR key
3. .sqinit decrypts .text using XTEA with page keys
4. Jump to original entry point (CRT init -> main)
5. anti_debug!() installs VEH + loads nanomite table
6. INT3 branches dispatched by VEH handler
7. Tidal Memory encrypts pages -> VEH decrypts on demand
```

---

## Comparison with Commercial Protectors

| Feature | VMProtect | Themida | SQURE |
|---------|-----------|---------|-------|
| Code Virtualization | Yes | Yes | Yes |
| Anti-Debug | 15+ checks | 20+ checks | 9+ checks |
| Anti-Dump | Yes | Yes | Yes (Tidal Memory) |
| Nanomite | Yes | Yes | Yes (VEH dispatch) |
| Metamorphic Engine | No | Yes | Yes |
| Process Guard | No | No | **Yes (3-process)** |
| Shamir Key Splitting | No | No | **Yes (3-of-3)** |
| Honeypot Traps | No | No | **Yes** |
| Cascade Integrity | No | No | **Yes** |
| Direct Syscall | No | No | **Yes** |
| Sandbox Detection | Yes | Yes | Yes (CPUID) |
| Open Source | No | No | **Yes (MIT)** |
| Price | $200-800 | $200-400 | **Free** |

---

## Troubleshooting

### Binary Crashes at Startup

1. Try `--no-encrypt-stub` to bypass .sqpre issues
2. Try `--no-nanomite` to disable INT3 patching
3. Use lower protection level first, then increase

### Antivirus False Positives

Some features (especially nanomites and VEH) may trigger AV heuristics. This is expected behavior for packers/protectors.

### Debugger Detection

1. Use `--no-anti-debug` flag for debugging
2. Configure debugger to pass INT3 exceptions to debuggee

---

## Security Considerations

SQURE is designed for **legitimate software protection**:
- Protect commercial software from piracy
- Prevent reverse engineering of proprietary algorithms
- Add tamper detection to security-critical applications

**Do not use for malware.** This tool is for defensive purposes only.

---

## License

MIT License - Free and open source.

## Contributing

Contributions welcome! Please feel free to submit issues and pull requests.

## Support

- GitHub Issues: Report bugs and request features
- Documentation: This file + README.md
