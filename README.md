# TVOSRecon

A comprehensive tvOS reconnaissance tool for security research. TVOSRecon systematically maps everything a sandboxed, sideloaded app can observe on an Apple TV 4K (A15 Bionic, tvOS 17+). When launched, it collects data from 33 probe modules and streams results as newline-delimited JSON to a companion listener on your local network.

> **This tool uses private APIs and direct syscalls that will not pass App Store review. It is intended exclusively for security research on devices you own.**

---

## Prerequisites

- **Xcode 15+** (with tvOS SDK)
- **Apple TV 4K** (3rd generation / A15 recommended; other models work with reduced coverage)
- **Apple Developer account** (free or paid — free accounts can sideload for 7 days)
- **Python 3.8+** on your laptop (for the companion listener)
- Both Apple TV and laptop on the **same local network**

---

## Building

### Automated (GitHub Actions)

Every push to `main` triggers a build that produces a signed IPA artifact. Go to **Actions > Build TVOSRecon > latest run > Artifacts** and download `TVOSRecon-IPA`.

### Local build

```bash
xcodebuild -project TVOSRecon.xcodeproj \
  -scheme TVOSRecon \
  -destination 'generic/platform=tvOS' \
  -configuration Release \
  CODE_SIGN_IDENTITY="-" \
  CODE_SIGNING_ALLOWED=NO \
  DEVELOPMENT_TEAM="" \
  PROVISIONING_PROFILE=""
```

The resulting `.app` bundle is in `build/Build/Products/Release-appletvos/`.

---

## Re-signing with Your Developer Certificate

The CI build uses ad-hoc signing (`CODE_SIGN_IDENTITY="-"`). To install on a real Apple TV you must re-sign with your developer identity.

### Option A: Xcode Automatic Signing

1. Open `TVOSRecon.xcodeproj` in Xcode.
2. Select the **TVOSRecon** target > **Signing & Capabilities**.
3. Check **Automatically manage signing**.
4. Select your **Team** from the dropdown.
5. Build and run targeting your Apple TV.

### Option B: codesign (command line)

```bash
# Find your signing identity
security find-identity -v -p codesigning

# Unzip the IPA
unzip TVOSRecon.ipa -d resigned
# Remove existing signature
rm -rf resigned/Payload/TVOSRecon.app/_CodeSignature

# Replace the embedded provisioning profile
cp /path/to/your/embedded.mobileprovision resigned/Payload/TVOSRecon.app/

# Re-sign
codesign -f -s "Apple Development: your@email.com (TEAMID)" \
  --entitlements entitlements.plist \
  resigned/Payload/TVOSRecon.app

# Re-package
cd resigned && zip -r ../TVOSRecon-resigned.ipa Payload
```

### Option C: iOS App Signer (GUI)

1. Download [iOS App Signer](https://dantheman827.github.io/ios-app-signer/).
2. Select the `.ipa` file as input.
3. Choose your signing certificate and provisioning profile.
4. Click **Start** to produce a re-signed IPA.

---

## Sideloading to Apple TV

### Enable Wireless Debugging

1. On Apple TV: **Settings > Remotes and Devices > Remote App and Devices** — ensure your Mac is paired.
2. In Xcode: **Window > Devices and Simulators** — your Apple TV should appear under **Discovered**.
3. If not visible, ensure both devices are on the same network and restart the Apple TV.

### Install via Xcode

1. Open **Window > Devices and Simulators** in Xcode.
2. Select your Apple TV.
3. Under **Installed Apps**, click **+** and choose the re-signed `.ipa`.
4. Alternatively, open the project and press **Cmd+R** with the Apple TV selected as destination.

### Install via Command Line

```bash
# Using ios-deploy (if tvOS support is available)
ios-deploy --bundle Payload/TVOSRecon.app

# Using pymobiledevice3
pymobiledevice3 apps install TVOSRecon-resigned.ipa
```

> Free developer accounts allow sideloading for 7 days. After that, you must re-sign and re-install.

---

## Running the Listener

On your laptop (same network as the Apple TV):

```bash
pip install zeroconf
python3 listener.py
```

The listener auto-discovers TVOSRecon via Bonjour. Once the app launches on the Apple TV, data streams in and is written to a timestamped file (`tvosrecon_YYYYMMDD_HHMMSS.json`).

### Manual connection (skip discovery)

```bash
python3 listener.py --host 192.168.1.50 --port 9100
```

---

## Attaching a Debugger with pymobiledevice3

[pymobiledevice3](https://github.com/doronz88/pymobiledevice3) lets you attach `lldb` to the running app for live inspection.

### Install

```bash
pip install pymobiledevice3
```

### Pair with Apple TV

```bash
# Over USB (USB-C cable)
pymobiledevice3 pair

# Over network (after initial USB pairing)
pymobiledevice3 remote pair
```

### Start a debug server and attach lldb

```bash
# Start the debug server on the device
pymobiledevice3 developer debugserver start

# In another terminal, attach lldb
pymobiledevice3 developer debugserver lldb-attach --name TVOSRecon
```

This gives you a full `lldb` session connected to the running TVOSRecon process on your Apple TV. From there you can inspect memory, set breakpoints, and explore further.

### Remote Service Discovery (network)

```bash
# Create a tunnel for network debugging
pymobiledevice3 remote start-tunnel

# Then use the tunnel address for lldb
pymobiledevice3 developer debugserver lldb-attach \
  --name TVOSRecon --tunnel <tunnel-address>
```

---

## Modules

| # | Module | Description |
|---|--------|-------------|
| 1 | **SystemInfo** | UIDevice, ProcessInfo, NSLocale — device identity, OS version, environment variables |
| 2 | **SysctlProbe** | Walks the entire sysctl MIB tree (CTL_KERN, CTL_HW, CTL_NET, etc.) and probes undocumented OIDs |
| 3 | **FileSystemWalker** | Recursively enumerates the filesystem — permissions, xattrs, symlinks, plist deserialization, first bytes of small files |
| 4 | **DyldCacheInspector** | Lists all loaded dylibs, parses Mach-O headers and load commands, probes private frameworks via dlopen/dlsym |
| 5 | **MachInspector** | Mach task/host/thread info, port enumeration, host_get_special_port, task_for_pid attempts |
| 6 | **IOKitExplorer** | Walks the full IORegistry across all planes, dumps properties, tests IOServiceOpen |
| 7 | **SandboxProfiler** | Calls sandbox_check for dozens of operations, tests empirical file access, probes sandbox extensions |
| 8 | **XPCServiceProber** | Enumerates XPC/launchd services from plists and tries connecting to each with a ping message |
| 9 | **NetworkProbe** | Interface enumeration, socket creation tests, DNS config, ARP/routing tables, NWPathMonitor |
| 10 | **SyscallProber** | Systematically invokes syscalls 0-600, tests fork/exec/ptrace/mmap, probes csops and MAC framework |
| 11 | **MemoryLayoutMapper** | Walks the entire virtual address space with vm_region, maps ASLR slides, tests kernel address reads |
| 12 | **EntitlementChecker** | Dumps entitlements blob, checks code signing flags, parses embedded.mobileprovision |
| 13 | **KeychainProbe** | Queries all keychain classes for accessible items and metadata, tests write access and access groups |
| 14 | **HardwareProbe** | CoreMotion, AVFoundation, UIScreen modes, CoreBluetooth, ExternalAccessory, CoreLocation |
| 15 | **ProcessEnumeration** | Lists all running processes (proc_listallpids), file descriptors, credentials, audit info |
| 16 | **ObjectiveCRuntime** | Enumerates all registered ObjC classes, protocols, methods, ivars on security-relevant classes |
| 17 | **MountedFilesystems** | Lists mounted filesystems with flags, pathconf values, storage stats |
| 18 | **ResourceLimits** | getrlimit/setrlimit for all resource types, sysconf values, confstr paths |
| 19 | **POSIXIPCProbe** | Tests shm_open, sem_open, mq_open, SysV IPC, unix socket discovery and connection |
| 20 | **DarwinNotifications** | Registers for Darwin notification center events and monitors which fire over 10 seconds |
| 21 | **NetworkServiceDiscovery** | Browses all Bonjour services on the local network via the meta-query, resolves instances |
| 22 | **URLSchemeProber** | Tests canOpenURL for dozens of URL schemes to fingerprint installed apps and system capabilities |
| 23 | **MetalGPUProbe** | Metal device info, GPU family support, capabilities, pixel format support, compute pipeline test |
| 24 | **MediaCapabilities** | Audio/video codec support, AVAudioSession details, hardware decode checks, audio components |
| 25 | **CryptoCapabilities** | Tests SecKey algorithms, Secure Enclave key generation, hash benchmarks, CryptoKit, trust anchors |
| 26 | **MachTrapProbe** | Probes mach trap numbers 0-127, tests thread state get/set, exception port manipulation |
| 27 | **ClockAndTimers** | Reads all clock sources, measures timer resolution, tests clock_settime, Mach time info |
| 28 | **PasteboardAndAppState** | UIPasteboard, UIApplication state, NSBundle info, UserDefaults, iCloud status |
| 29 | **OSLogProbe** | Reads system logs via OSLogStore if accessible, tries ASL and direct log file reads |
| 30 | **ThermalAndPowerProbe** | Thermal state, IOKit thermal sensors, power management data |
| 31 | **DispatchAndGCDProbe** | GCD QoS classes, thread pool sizing, dispatch source types, pthread attributes |
| 32 | **AccessibilityAndUIProbe** | Accessibility settings, UIFocusSystem, UITraitCollection, display configuration |
| 33 | **CompilerAndRuntimeInfo** | Swift/ObjC runtime versions, JIT availability, dyld info, TargetConditionals |

---

## Architecture

```
TVOSReconApp (SwiftUI)
  |
  +-- ContentView         Status UI: module name, progress %, Bonjour address
  |
  +-- ReconEngine         Orchestrates modules sequentially on a background queue
  |     |                 Enforces per-module timeouts (60s default, 120s for heavy)
  |     |                 Catches crashes per module via signal handlers
  |     |
  |     +-- [ReconModule] Array of 33 module instances
  |
  +-- NetworkServer       TCP server on port 9100
  |     |                 Bonjour advertisement (_tvosrecon._tcp)
  |     |                 Streams NDJSON to connected clients
  |
  +-- LocalLogger         Writes all results to a log file in the app container
```

Each module conforms to the `ReconModule` protocol and calls `engine.report(...)` to emit results. Results are:
- Streamed live over TCP to any connected listener
- Written to a local JSON log as backup
- Counted for the progress indicator

JSON line format:
```json
{"module": "SystemInfo", "key": "device.model", "value": "AppleTV11,1", "error": null}
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.

This tool is provided for authorized security research only. Use it responsibly and only on devices you own.
