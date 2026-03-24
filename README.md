```
 ___.                 __                            ___.
 \_ |_________ __ ___/  |_  ____   ________________ \_ |__   ___________
  | __ \_  __ \  |  \   __\/ __ \_/ ___\_  __ \__  \ | __ \_/ __ \_  __ \
  | \_\ \  | \/  |  /|  | \  ___/\  \___|  | \// __ \| \_\ \  ___/|  | \/
  |___  /__|  |____/ |__|  \___  >\___  >__|  (____  /___  /\___  >__|
      \/                       \/     \/           \/    \/     \/
```

# 🦀 BruteCraber

A fast MD5 hash cracker using wordlist-based dictionary attacks. Built with Rust.

## ✨ Features

- 🔓 MD5 hash cracking via wordlist
- 🎨 Colored output
- ⚡ Clean CLI interface with `-f` and `-w` flags

## 📦 Installation

```bash
git clone https://github.com/erikgavs/brutecraber.git
cd brutecraber
cargo build --release
```

The binary will be at `./target/release/brutecraber`.

## 🚀 Usage

```bash
./brutecraber -f <hashes_file> -w <wordlist>
```

### 📝 Example

```bash
./brutecraber -f hashes.txt -w wordlist.txt
```

### 🔧 Options

| Flag | Description |
|------|-------------|
| `-f` | Path to file containing MD5 hashes (one per line) |
| `-w` | Path to wordlist file |
| `-h` | Show help |

## 📄 Hash file format

One hash per line:

```
900150983cd24fb0d6963f7d28e17f72
e99a18c428cb38d5f260853678922e03
827ccb0eea8a706c4c34a16891f84e7b
```

## ⚠️ Disclaimer

This tool is intended for **ethical hacking and educational purposes only**. Unauthorized use against systems without prior consent is illegal. Use at your own risk.

## 👤 Author

**erikgavs**
