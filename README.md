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

### macOS: Gatekeeper Warning

macOS may display:
> Apple could not verify "SeestarTool" is free of malware that may harm your Mac or compromise your privacy.

This occurs because the app is not code-signed. You can safely bypass this by:

**Option 1: Right-click to open**
1. Right-click (or Ctrl+click) the app in Finder
2. Select **Open** from the context menu
3. Click **Open** in the confirmation dialog

**Option 2: Terminal command**
```bash
xattr -d com.apple.quarantine /Applications/SeestarTool.app
```

Then open the app normally. This removes the quarantine flag that triggers the warning.

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

### About Firmware Files

**Why APK?**

ZWO distributes Seestar firmware bundled inside the Android companion app APK (Android Package). The app itself runs on your phone, but it also carries the telescope's firmware as an embedded asset. An APK is a ZIP archive, so this tool unpacks it, extracts the firmware binary (`iscope` or `iscope_64`), and uploads it directly to your scope.

**APK vs. XAPK**

- **APK** — a single archive file containing all firmware components
- **XAPK** — a split APK format used for large packages; it's a ZIP containing multiple APK files plus metadata

Both formats can be used with this tool—it handles the extraction automatically.

**What is `iscope`?**

`iscope` comes in two variants:

- **`iscope`** — 32-bit firmware binary (used on earlier Seestar models)
- **`iscope_64`** — 64-bit firmware binary (used on Seestar S30 and S30 Pro)

Both are bzip2-compressed tarballs containing the firmware binary and related system files, stored in the APK's `assets/iscope` or `assets/iscope_64` entry. This tool automatically detects and extracts the correct variant from your APK. You can:

- Extract and use a raw `iscope` or `iscope_64` file directly
- Let this tool extract the appropriate variant from an APK/XAPK before uploading
- Extract it as a reference or for use with other tools (e.g., [seestar_alp](https://github.com/smart-underworld/seestar_alp))

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

## Interoperability and Legal Notice (Extract PEM)

PEM key extraction is provided for **interoperability purposes** under 17 U.S.C. § 1201(f) — the DMCA interoperability exemption. That provision permits circumvention of access controls solely to the extent necessary to achieve interoperability of an independently created program with other programs. Extraction of the TLS private key is performed to enable independent software (such as [seestar_alp](https://github.com/smart-underworld/seestar_alp)) to interoperate with the Seestar device's local API.

**The legality of key extraction and use varies by jurisdiction.** The DMCA interoperability exemption applies within the United States. Laws governing reverse engineering, circumvention, and interoperability differ significantly across countries and regions. **You are solely responsible for ensuring that your use of this feature complies with the laws of your region.**

The author(s) of this software make no representations regarding the legality of this feature outside the United States, and expressly disclaim any liability arising from use of the Extract PEM feature in jurisdictions where such activity may not be permitted.

---

## Versions

Known firmware version number mappings:

| App version | asiair version_int | version_string |
|---|---|---|
| 3.1.2 | 2732 | 7.32 |
| 3.1.1 | 2718 | 7.18 |
| 3.1.0 | 2706 | 7.06 |
| 3.0.2 | 2670 | 6.70 |
| 3.0.1 | 2658 | 6.58 |
| 3.0.0 | 2645 | 6.45 |
| 2.7.0 | 2597 | 5.97 |
| 2.6.4 | 2582 | 5.82 |
| 2.6.1 | 2550 | 5.50 |
| 2.6.0 | 2534 | 5.34 |
| 2.5.0 | 2470 | 4.70 |
| 2.4.1 | 2443 | 4.43 |
| 2.4.0 | 2427 | 4.27 |
| 2.3.1 | 2402 | 4.02 |
| 2.3.0 | 2400 | 4.00 |
| 2.2.1 | 2368 | 3.68 |
| 2.2.0 | 2358 | 3.58 |
| 2.1.0 | 2331 | 3.31 |
| 2.0.0 | 2295 | 2.95 |
| 1.20.2 | 2276 | 2.76 |
| 1.20.0 | 2271 | 2.71 |
| 1.19.0 | 2261 | 2.61 |
| 1.18.0 | 2253 | 2.53 |

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
