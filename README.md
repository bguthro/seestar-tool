# Seestar Tool

A native desktop application for managing firmware on ZWO Seestar smart telescopes.

Built with [egui](https://github.com/emilk/egui) and Rust.

---

## Features

- **Firmware Update** — install firmware directly from a local APK/XAPK file, a raw `iscope` binary, or downloaded from APKPure
- **Extract PEM** — extract the TLS private key from a Seestar APK for use with local API access
- Animated progress bar with installation countdown
- Color-coded output log

## Building

Requires the [Rust toolchain](https://rustup.rs/).

```bash
cargo build --release
```

The binary will be at `target/release/seestar-tool`.

## Usage

### Firmware Update

1. Choose a firmware source:
   - **Local APK / XAPK** — pick a `.apk` or `.xapk` file you already have
   - **Local iscope** — pick a raw extracted `iscope` firmware binary
   - **Download from APKPure** — fetch a version list and download directly
2. Enter your Seestar's IP address or hostname (default: `seestar.local`)
3. Click **Update Seestar** or **Download & Install**

The app connects to the scope's OTA updater on port 4350/4361, uploads the firmware, and monitors the reboot. A progress bar counts down the estimated install time (~3 minutes), then waits for the scope to come back online.

### Extract PEM

Pick a Seestar APK/XAPK and click **Extract PEM Key**. The key can be saved to a `.pem` file for use with local HTTPS API access.

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
