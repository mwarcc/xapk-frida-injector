# Frida XAPK Injector

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Platform Android](https://img.shields.io/badge/Platform-Android-3DDC84?logo=android&logoColor=white)](https://developer.android.com/)
[![License MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Automated instrumentation pipeline for Android application analysis.**

`frida-xapk-injector` is a specialized tool designed to streamline the process of reverse engineering Android applications distributed as **XAPK bundles** (Split APKs). It automates the conversion of fragmented APKs into a single monolithic package, sanitizes the manifest, and injects the **Frida Gadget** dynamic instrumentation library directly into the Smali bytecode.

This tool eliminates the need for a rooted device to inspect network traffic, bypass SSL pinning, or hook internal methods on complex modern applications.

## ⚡ Key Capabilities

### 1. Advanced XAPK Handling
- **Split APK Merging:** Automatically identifies and merges configuration splits (density, language, ABI) into the base APK.
- **Resource consolidation:** intelligently maps split assets back to the standard Android directory structure.

### 2. Smali Bytecode Injection
- **Dynamic Entry Point Detection:** Parses the manifest to locate the main `Launcher Activity`.
- **Smali Patching:** Injects the `System.loadLibrary("frida-gadget")` call directly into the activity's constructor (`<init>` or `<clinit>`) to ensure early execution.

### 3. Manifest Sanitization
- **Restriction Bypassing:** Strips `isSplitRequired` and other Android App Bundle metadata that prevents merged APKs from installing.
- **Security Flag Override:** Enforces `android:debuggable="true"` and `android:extractNativeLibs="true"`.
- **Network Permissiveness:** Enables `usesCleartextTraffic` and ensures `INTERNET` permissions are present.

### 4. Smart Compression Strategy
- Implements a context-aware compression policy during recompilation.
- Ensures native libraries (`.so`) are stored **uncompressed** (STORED method) to comply with Android 11+ alignment requirements (`zipalign` logic).

---

## 🛠️ Prerequisites

To run this pipeline, ensure your environment meets the following requirements:

- **Python 3.10+**
- **Java Runtime Environment (JRE) 11+** (Must be in your system `$PATH`)
- **External Tools:**
  Place the following JAR files in the root directory of the project:
  1. `apktool.jar` (v2.7.0 or newer recommended)
  2. `signer.jar` (e.g., [uber-apk-signer](https://github.com/patrickfav/uber-apk-signer))

## 📦 Installation

```bash
git clone https://github.com/YOUR_USERNAME/frida-xapk-injector.git
cd frida-xapk-injector
```

No pip install required. The tool relies exclusively on the Python Standard Library for maximum portability.

## 🚀 Usage
Execute the script by passing the target .xapk or .apk file path:

```bash
python3 injector.py /path/to/application.xapk
```

The Pipeline Process

    Acquisition: Downloads 16.2.1 frida-gadget-arm64.so.
    Extraction & Merge: Unpacks the XAPK and consolidates split binaries.
    Decompilation: Disassembles the DEX bytecode into Smali.
    Injection: Patches the entry point and native libraries.
    Build: Recompiles the modified artifacts.
    Signing: Signs the final APK with a debug certificate.

## Output

The patched artifact will be generated in the working directory:
application_frida.apk,
You can deploy it using ADB:
```bash
adb install application_frida.apk
```
