# Seestar Tool

A native desktop application for managing firmware on ZWO Seestar smart telescopes.

Built with [egui](https://github.com/emilk/egui) and Rust. Available as a GUI and a `--tui` terminal interface.

---

## Features

- **Firmware Update** — install firmware from a local APK/XAPK file, a raw `iscope` binary, or downloaded directly from APKPure
- **Download Only** — fetch a firmware APK without immediately flashing it
- **Extract PEM** — extract the TLS private key from a Seestar APK for use with local API access
- Animated progress bar with installation countdown
- Color-coded output log
- Confirmation dialog before any firmware flash

## Installation

Pre-built binaries are available on the [Releases](../../releases) page for:

| Platform | File |
|---|---|
| macOS (Apple Silicon) | `seestar-tool-aarch64-apple-darwin-*.dmg` |
| macOS (Intel) | `seestar-tool-x86_64-apple-darwin-*.dmg` |
| Linux x86_64 | `seestar-tool_*_amd64.deb` |
| Linux arm64 | `seestar-tool_*_arm64.deb` |
| Windows x86_64 | `seestar-tool-x86_64-pc-windows-msvc-*.zip` |

**macOS:** Open the `.dmg` and drag Seestar Tool to Applications.

**Linux:** `sudo dpkg -i seestar-tool_*.deb`

**Windows:** Extract the `.zip` and run `seestar-tool.exe`.

## Building from source

Requires the [Rust toolchain](https://rustup.rs/).

```bash
cargo build --release
```

The binary will be at `target/release/seestar-tool`.

**Linux** also requires GUI system libraries:

```bash
sudo apt-get install libgtk-3-dev libxcb-render0-dev libxcb-shape0-dev \
  libxcb-xfixes0-dev libxkbcommon-dev libssl-dev libfontconfig1-dev libgl1-mesa-dev
```

## Usage

### GUI (default)

```bash
seestar-tool
```

### Terminal UI

```bash
seestar-tool --tui
```

---

### Firmware Update

1. Choose a firmware source:
   - **Local APK / XAPK** — pick a `.apk` or `.xapk` file you already have
   - **Local iscope** — pick a raw extracted `iscope` firmware binary
   - **Download from APKPure** — fetch a version list and download directly
2. Enter your Seestar's IP address or hostname (default: `seestar.local`)
3. Click **Update Seestar** (or **Download & Install**) and confirm the dialog

The app connects to the scope's OTA updater, uploads the firmware, and monitors the reboot. A progress bar counts down the estimated install time (~3 minutes), then waits for the scope to come back online.

### Extract PEM

Pick a Seestar APK/XAPK and click **Extract PEM Key**. The extracted key can be saved to a `.pem` file.

> **Interoperability Notice:** PEM key extraction is provided for interoperability purposes under 17 U.S.C. § 1201(f) (the DMCA interoperability exemption), enabling independent programs to interoperate with your Seestar device. The legality of key extraction and use varies by jurisdiction. You are solely responsible for ensuring compliance with the laws of your region.

---

## Disclaimer and Warning

> **Read carefully before use.**

### Not affiliated with or supported by ZWO

This project is **independent, unofficial, and unsupported**. It is not affiliated with, endorsed by, or supported by ZWO Co., Ltd. in any way. "Seestar" is a trademark of ZWO Co., Ltd. Use of that name here is purely descriptive.

### Warranty

**Using this tool to flash firmware onto your Seestar telescope may void your manufacturer's warranty.** ZWO may refuse to service or repair devices whose firmware has been modified or replaced through unofficial means. You use this tool entirely at your own risk.

### Risk of firmware flashing

Flashing firmware to any device carries inherent risks. Interrupting the process, using incompatible firmware, or encountering unexpected hardware or software conditions can result in the device becoming **non-functional ("bricked")**. There is no guaranteed recovery path. Before proceeding:

- Ensure the scope is fully charged and will not lose power during the update
- Ensure your network connection is stable throughout the upload
- Verify you are using a firmware version intended for your specific hardware

### Assumption of risk

By using this software, **you acknowledge and accept full responsibility for any outcome**, including but not limited to: damage to your equipment, loss of data, voided warranty, or device failure. The author(s) of this software provide it "as-is", without warranty of any kind, express or implied.

### Limitation of liability

**The author(s) of this software shall not be held liable for any direct, indirect, incidental, special, or consequential damages arising from the use or misuse of this software**, regardless of whether such damages were foreseeable. This includes, without limitation, damage to your telescope, loss of use, or any costs incurred as a result of device failure or repair.

By downloading, building, or running this software, you agree to these terms.

---

## License

GPL v3 — see [LICENSE](LICENSE).
