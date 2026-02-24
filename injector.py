#!/usr/bin/env python3

import os
import sys
import json
import shutil
import zipfile
import subprocess
import re
import urllib.request
import lzma
import traceback
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class Architecture(Enum):
    ARM64 = "arm64-v8a"
    ARM32 = "armeabi-v7a"
    X86 = "x86"
    X86_64 = "x86_64"


class LogLevel(Enum):
    INFO = "INFO"
    SUCCESS = " OK "
    WARNING = "WARN"
    ERROR = "ERR "
    SECTION = ">>>>"


@dataclass(frozen=True)
class GadgetSource:
    version: str = "16.2.1"
    arch: Architecture = Architecture.ARM64

    @property
    def url(self) -> str:
        return "https://github.com/frida/frida/releases/download/16.2.1/frida-gadget-16.2.1-android-arm64.so.xz"

    @property
    def library_name(self) -> str:
        return "libfrida-gadget.so"

    @property
    def loader_name(self) -> str:
        return "frida-gadget"


@dataclass(frozen=True)
class ProjectPaths:
    root: Path

    @property
    def work_dir(self) -> Path:
        return self.root / "xapk_work"

    @property
    def apktool_jar(self) -> Path:
        return self.root / "apktool.jar"

    @property
    def signer_jar(self) -> Path:
        return self.root / "signer.jar"

    @property
    def log_file(self) -> Path:
        return self.root / "converter.log"

    @property
    def extracted_dir(self) -> Path:
        return self.work_dir / "extracted"

    @property
    def decompiled_dir(self) -> Path:
        return self.work_dir / "decompiled"

    @property
    def merged_apk(self) -> Path:
        return self.work_dir / "merged.apk"

    @property
    def unsigned_apk(self) -> Path:
        return self.work_dir / "unsigned.apk"


@dataclass
class ManifestPolicy:
    strip_split_attributes: list = field(default_factory=lambda: [
        "requiredSplitTypes", "splitTypes", "isSplitRequired", "split",
        "splitName", "configForSplit", "isolatedSplits", "requiredSplitFeatures",
    ])

    strip_metadata_keywords: list = field(default_factory=lambda: [
        "vending.splits", "vending.derived", "android.stamp", "com.android.dynamic",
    ])

    enforce_attributes: dict = field(default_factory=lambda: {
        "extractNativeLibs": "true",
        "debuggable": "true",
        "usesCleartextTraffic": "true",
    })

    required_permissions: list = field(default_factory=lambda: [
        "android.permission.INTERNET",
    ])


@dataclass
class CompressionPolicy:
    store_patterns: tuple = (
        ".so", ".dat", ".assets", ".bundle", ".unity3d",
    )
    store_filenames: tuple = (
        "resources.arsc",
    )

    def should_store(self, filename: str) -> bool:
        if filename in self.store_filenames:
            return True
        if filename.endswith(self.store_patterns) and "lib/" in filename:
            return True
        if filename.endswith(self.store_patterns[1:]):
            return True
        return False


# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------


class Logger:
    def __init__(self, log_path: Path):
        self._path = log_path
        self._init_log_file()

    def _init_log_file(self) -> None:
        try:
            self._path.write_text(
                f"=== Session started at {datetime.now().isoformat()} ===\n",
                encoding="utf-8",
            )
        except OSError:
            pass

    def _emit(self, level: LogLevel, message: str) -> None:
        line = f"[{level.value}] {message}"
        print(line)
        try:
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except OSError:
            pass

    def info(self, message: str) -> None:
        self._emit(LogLevel.INFO, message)

    def success(self, message: str) -> None:
        self._emit(LogLevel.SUCCESS, message)

    def warning(self, message: str) -> None:
        self._emit(LogLevel.WARNING, message)

    def error(self, message: str) -> None:
        self._emit(LogLevel.ERROR, message)

    def section(self, message: str) -> None:
        self._emit(LogLevel.SECTION, message)

    @staticmethod
    def banner() -> None:
        print("\n" + "=" * 50)
        print("  XAPK → APK + Frida Gadget Injector")
        print("=" * 50 + "\n")


# ---------------------------------------------------------------------------
# Shell command runner
# ---------------------------------------------------------------------------


@dataclass
class CommandResult:
    return_code: int
    stdout: str
    stderr: str

    @property
    def success(self) -> bool:
        return self.return_code == 0


class Shell:
    def __init__(self, logger: Logger):
        self._log = logger

    def execute(
        self,
        command: list[str],
        working_dir: Optional[Path] = None,
        timeout: int = 600,
    ) -> CommandResult:
        preview = " ".join(str(token) for token in command[:6])
        self._log.info(f"Executing: {preview}")

        try:
            process = subprocess.run(
                command,
                cwd=working_dir,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
            result = CommandResult(
                return_code=process.returncode,
                stdout=process.stdout or "",
                stderr=process.stderr or "",
            )
        except subprocess.TimeoutExpired:
            result = CommandResult(-1, "", "Command timed out")
        except FileNotFoundError:
            result = CommandResult(-1, "", "Command not found")
        except Exception as exc:
            result = CommandResult(-1, "", str(exc))

        if not result.success and result.stderr:
            self._log.warning(result.stderr[:500])

        return result


# ---------------------------------------------------------------------------
# Java runtime locator
# ---------------------------------------------------------------------------


class JavaRuntime:
    def __init__(self, shell: Shell):
        self._shell = shell
        self._binary: Optional[str] = None

    def locate(self) -> str:
        if self._binary:
            return self._binary

        candidates = ["java"]

        java_home = os.environ.get("JAVA_HOME")
        if java_home:
            candidates.insert(0, os.path.join(java_home, "bin", "java"))

        for candidate in candidates:
            result = self._shell.execute([candidate, "-version"])
            if result.success:
                self._binary = candidate
                return candidate

        raise EnvironmentError(
            "Java runtime not found. Install JDK 11+ or set JAVA_HOME."
        )


# ---------------------------------------------------------------------------
# Frida Gadget downloader
# ---------------------------------------------------------------------------


class GadgetDownloader:
    def __init__(self, source: GadgetSource, work_dir: Path, logger: Logger):
        self._source = source
        self._work_dir = work_dir
        self._log = logger

    @property
    def _so_path(self) -> Path:
        return self._work_dir / self._source.library_name

    @property
    def _xz_path(self) -> Path:
        return self._work_dir / "gadget.so.xz"

    def ensure_available(self) -> Path:
        self._log.section("Acquiring Frida Gadget")

        if self._so_path.exists():
            self._log.success("Gadget already cached locally")
            return self._so_path

        self._log.info(f"Downloading: {self._source.url}")
        try:
            urllib.request.urlretrieve(self._source.url, str(self._xz_path))
        except Exception as exc:
            raise RuntimeError(f"Gadget download failed: {exc}") from exc

        self._log.info("Decompressing archive")
        try:
            with lzma.open(self._xz_path) as compressed:
                with self._so_path.open("wb") as output:
                    shutil.copyfileobj(compressed, output)
        except Exception as exc:
            raise RuntimeError(f"Gadget decompression failed: {exc}") from exc

        self._log.success("Gadget ready")
        return self._so_path


# ---------------------------------------------------------------------------
# XAPK extractor and APK merger
# ---------------------------------------------------------------------------


@dataclass
class ExtractionResult:
    merged_apk: Path
    package_name: str


class XapkExtractor:
    def __init__(self, paths: ProjectPaths, logger: Logger):
        self._paths = paths
        self._log = logger

    def extract_and_merge(self, xapk_path: Path) -> ExtractionResult:
        self._log.section("Extracting XAPK")
        self._prepare_staging()
        self._unzip(xapk_path)

        package_name = self._read_package_name()
        self._log.info(f"Package: {package_name}")

        base_apk, split_apks = self._classify_apks()
        self._log.info(f"Base APK: {base_apk.name}")
        self._log.info(f"Split APKs found: {len(split_apks)}")

        self._create_merged_apk(base_apk, split_apks)
        self._log.success("APK merge complete")

        return ExtractionResult(
            merged_apk=self._paths.merged_apk,
            package_name=package_name,
        )

    def _prepare_staging(self) -> None:
        if self._paths.extracted_dir.exists():
            shutil.rmtree(self._paths.extracted_dir, ignore_errors=True)
        self._paths.extracted_dir.mkdir(parents=True, exist_ok=True)

    def _unzip(self, xapk_path: Path) -> None:
        with zipfile.ZipFile(xapk_path, "r") as archive:
            archive.extractall(self._paths.extracted_dir)

    def _read_package_name(self) -> str:
        manifest = self._paths.extracted_dir / "manifest.json"
        if not manifest.is_file():
            return "unknown"
        try:
            with manifest.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            return data.get("package_name", "unknown")
        except (json.JSONDecodeError, OSError):
            return "unknown"

    def _classify_apks(self) -> tuple[Path, list[Path]]:
        base_apk: Optional[Path] = None
        split_apks: list[Path] = []

        for path in self._paths.extracted_dir.rglob("*.apk"):
            if self._is_split_apk(path.name):
                split_apks.append(path)
            else:
                base_apk = path

        if base_apk is None:
            if split_apks:
                base_apk = split_apks.pop(0)
            else:
                raise FileNotFoundError("No APK files found inside XAPK archive")

        return base_apk, split_apks

    @staticmethod
    def _is_split_apk(filename: str) -> bool:
        return "config" in filename or "split" in filename

    def _create_merged_apk(self, base: Path, splits: list[Path]) -> None:
        shutil.copy2(base, self._paths.merged_apk)

        if not splits:
            return

        skip_prefixes = ("AndroidManifest", "META-INF")

        with zipfile.ZipFile(self._paths.merged_apk, "a") as target:
            existing_entries = set(target.namelist())

            for split_path in splits:
                with zipfile.ZipFile(split_path, "r") as source:
                    for entry_name in source.namelist():
                        if entry_name in existing_entries:
                            continue
                        if any(entry_name.startswith(p) for p in skip_prefixes):
                            continue
                        target.writestr(entry_name, source.read(entry_name))
                        existing_entries.add(entry_name)


# ---------------------------------------------------------------------------
# Apktool wrapper (decompile / recompile)
# ---------------------------------------------------------------------------


class ApktoolBridge:
    def __init__(
        self,
        java: JavaRuntime,
        paths: ProjectPaths,
        shell: Shell,
        logger: Logger,
        compression: CompressionPolicy,
    ):
        self._java = java
        self._paths = paths
        self._shell = shell
        self._log = logger
        self._compression = compression

    def decompile(self, apk_path: Path) -> Path:
        self._log.section("Decompiling APK")

        if self._paths.decompiled_dir.exists():
            shutil.rmtree(self._paths.decompiled_dir)

        java_bin = self._java.locate()
        result = self._shell.execute([
            java_bin, "-jar", str(self._paths.apktool_jar),
            "d", str(apk_path),
            "-o", str(self._paths.decompiled_dir),
            "-f",
        ])

        if not result.success:
            raise RuntimeError(f"Decompilation failed:\n{result.stderr}")

        self._log.success("Decompilation complete")
        return self._paths.decompiled_dir

    def recompile(self) -> Path:
        self._log.section("Recompiling APK")
        output = self._paths.unsigned_apk
        java_bin = self._java.locate()

        result = self._shell.execute([
            java_bin, "-jar", str(self._paths.apktool_jar),
            "b", str(self._paths.decompiled_dir),
            "-o", str(output),
            "--use-aapt2",
        ])

        if not result.success:
            self._log.warning("aapt2 build failed, retrying without it")
            result = self._shell.execute([
                java_bin, "-jar", str(self._paths.apktool_jar),
                "b", str(self._paths.decompiled_dir),
                "-o", str(output),
            ])
            if not result.success:
                raise RuntimeError(f"Recompilation failed:\n{result.stderr}")

        self._normalize_compression(output)
        self._log.success("Recompilation complete")
        return output

    def _normalize_compression(self, apk_path: Path) -> None:
        temp = apk_path.with_suffix(".tmp")

        with zipfile.ZipFile(apk_path, "r") as source:
            with zipfile.ZipFile(temp, "w", zipfile.ZIP_DEFLATED) as target:
                for entry in source.infolist():
                    data = source.read(entry.filename)
                    if self._compression.should_store(entry.filename):
                        entry.compress_type = zipfile.ZIP_STORED
                    target.writestr(entry, data)

        temp.replace(apk_path)


# ---------------------------------------------------------------------------
# AndroidManifest.xml patcher
# ---------------------------------------------------------------------------


class ManifestPatcher:
    def __init__(self, decompiled_dir: Path, policy: ManifestPolicy, logger: Logger):
        self._manifest_path = decompiled_dir / "AndroidManifest.xml"
        self._policy = policy
        self._log = logger

    def apply(self) -> None:
        self._log.section("Patching AndroidManifest.xml")
        content = self._read()
        content = self._strip_split_attributes(content)
        content = self._strip_metadata(content)
        content = self._enforce_application_attributes(content)
        content = self._ensure_permissions(content)
        self._write(content)
        self._log.success("Manifest patched")

    def _read(self) -> str:
        return self._manifest_path.read_text(encoding="utf-8", errors="ignore")

    def _write(self, content: str) -> None:
        self._manifest_path.write_text(content, encoding="utf-8")

    def _strip_split_attributes(self, content: str) -> str:
        for attr in self._policy.strip_split_attributes:
            content = re.sub(rf'\s*android:{attr}\s*=\s*"[^"]*"', "", content)
        return content

    def _strip_metadata(self, content: str) -> str:
        return "\n".join(
            line for line in content.splitlines()
            if not any(keyword in line for keyword in self._policy.strip_metadata_keywords)
        )

    def _enforce_application_attributes(self, content: str) -> str:
        for attr, value in self._policy.enforce_attributes.items():
            content = self._set_application_attribute(content, attr, value)
        return content

    @staticmethod
    def _set_application_attribute(content: str, attr: str, value: str) -> str:
        pattern = rf'(android:{attr}\s*=\s*)"[^"]*"'
        if re.search(pattern, content):
            return re.sub(pattern, rf'\1"{value}"', content)
        return re.sub(
            r"(<application\b)",
            rf'\1 android:{attr}="{value}"',
            content,
            count=1,
        )

    def _ensure_permissions(self, content: str) -> str:
        for permission in self._policy.required_permissions:
            if permission not in content:
                declaration = f'<uses-permission android:name="{permission}"/>'
                content = content.replace("<application", f"{declaration}\n<application")
        return content

    def resolve_launcher_activity(self) -> str:
        content = self._read()

        match = re.search(
            r'<activity[^>]*android:name="([^"]+)"[^>]*>.*?'
            r'android\.intent\.action\.MAIN',
            content,
            re.DOTALL,
        )
        if not match:
            match = re.search(r'<activity[^>]*android:name="([^"]+)"', content)

        if not match:
            raise RuntimeError(
                "Could not determine launcher activity from manifest"
            )

        return match.group(1)


# ---------------------------------------------------------------------------
# Frida Gadget injector (smali patching)
# ---------------------------------------------------------------------------


class GadgetInjector:
    SMALI_LOAD_TEMPLATE = (
        '\n    const-string v0, "{loader_name}"'
        "\n    invoke-static {{v0}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n"
    )

    SMALI_CLINIT_TEMPLATE = (
        "\n.method static constructor <clinit>()V"
        "\n    .locals 1"
        "\n{load_code}"
        "\n    return-void"
        "\n.end method\n"
    )

    def __init__(
        self,
        decompiled_dir: Path,
        gadget_path: Path,
        gadget_source: GadgetSource,
        logger: Logger,
    ):
        self._decompiled = decompiled_dir
        self._gadget_path = gadget_path
        self._source = gadget_source
        self._log = logger

    def inject(self, activity_class: str) -> None:
        self._log.section("Injecting Frida Gadget")
        self._place_native_library()
        self._patch_smali(activity_class)
        self._log.success("Gadget injection complete")

    def _place_native_library(self) -> None:
        lib_dir = self._decompiled / "lib" / self._source.arch.value
        lib_dir.mkdir(parents=True, exist_ok=True)

        destination = lib_dir / self._source.library_name
        shutil.copy2(self._gadget_path, destination)
        self._log.info(f"Placed native library: {destination.relative_to(self._decompiled)}")

    def _patch_smali(self, activity_class: str) -> None:
        self._log.info(f"Target activity: {activity_class}")

        smali_path = self._locate_smali(activity_class)
        if smali_path is None:
            raise FileNotFoundError(
                f"Smali file not found for class: {activity_class}"
            )

        self._log.info(f"Patching: {smali_path.relative_to(self._decompiled)}")

        code = smali_path.read_text(encoding="utf-8")
        load_code = self.SMALI_LOAD_TEMPLATE.format(loader_name=self._source.loader_name)

        if "<clinit>" in code:
            code = code.replace("return-void", load_code + "\n    return-void", 1)
        else:
            code += self.SMALI_CLINIT_TEMPLATE.format(load_code=load_code)

        smali_path.write_text(code, encoding="utf-8")

    def _locate_smali(self, class_name: str) -> Optional[Path]:
        relative_path = class_name.replace(".", os.sep) + ".smali"
        short_name = class_name.rsplit(".", 1)[-1] + ".smali"

        for root, _, files in os.walk(self._decompiled):
            root_path = Path(root)
            candidate = root_path / relative_path
            if candidate.is_file():
                return candidate
            if short_name in files:
                return root_path / short_name

        return None


# ---------------------------------------------------------------------------
# APK signer
# ---------------------------------------------------------------------------


class ApkSigner:
    def __init__(self, java: JavaRuntime, paths: ProjectPaths, shell: Shell, logger: Logger):
        self._java = java
        self._paths = paths
        self._shell = shell
        self._log = logger

    def sign(self, unsigned_apk: Path, output_path: Path) -> None:
        self._log.section("Signing APK")

        java_bin = self._java.locate()
        self._shell.execute([
            java_bin, "-jar", str(self._paths.signer_jar),
            "--apks", str(unsigned_apk),
            "--allowResign", "--overwrite",
        ])

        signed = self._find_signed_output(unsigned_apk.parent)
        if signed:
            shutil.move(str(signed), str(output_path))
            self._log.success(f"Signed APK: {output_path.name}")
        else:
            shutil.copy2(unsigned_apk, output_path)
            self._log.warning("Signer produced no output, copied unsigned APK")

    @staticmethod
    def _find_signed_output(directory: Path) -> Optional[Path]:
        for item in directory.iterdir():
            if item.suffix == ".apk" and "signed" in item.name.lower():
                return item
        return None


# ---------------------------------------------------------------------------
# Pipeline orchestrator
# ---------------------------------------------------------------------------


class Pipeline:
    def __init__(self, xapk_path: Path, output_path: Path):
        self._xapk = xapk_path
        self._output = output_path
        self._paths = ProjectPaths(root=Path.cwd())
        self._log = Logger(self._paths.log_file)
        self._shell = Shell(self._log)
        self._java = JavaRuntime(self._shell)
        self._gadget_source = GadgetSource()
        self._manifest_policy = ManifestPolicy()
        self._compression_policy = CompressionPolicy()

    def execute(self) -> None:
        self._log.banner()
        self._prepare_workspace()
        self._java.locate()

        gadget = GadgetDownloader(
            self._gadget_source, self._paths.work_dir, self._log,
        ).ensure_available()

        extraction = XapkExtractor(
            self._paths, self._log,
        ).extract_and_merge(self._xapk)

        apktool = ApktoolBridge(
            self._java, self._paths, self._shell,
            self._log, self._compression_policy,
        )
        decompiled = apktool.decompile(extraction.merged_apk)

        manifest = ManifestPatcher(decompiled, self._manifest_policy, self._log)
        manifest.apply()

        launcher = manifest.resolve_launcher_activity()

        GadgetInjector(
            decompiled, gadget, self._gadget_source, self._log,
        ).inject(launcher)

        unsigned = apktool.recompile()

        ApkSigner(
            self._java, self._paths, self._shell, self._log,
        ).sign(unsigned, self._output)

        self._print_summary(extraction.package_name)

    def _prepare_workspace(self) -> None:
        if self._paths.work_dir.exists():
            shutil.rmtree(self._paths.work_dir, ignore_errors=True)
        self._paths.work_dir.mkdir(parents=True, exist_ok=True)

    def _print_summary(self, package_name: str) -> None:
        divider = "=" * 60
        print(
            f"\n{divider}"
            f"\n  Output: {self._output.name}"
            f"\n{divider}"
            f"\n  adb uninstall {package_name}"
            f'\n  adb install "{self._output}"'
            f"\n{divider}\n"
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {Path(sys.argv[0]).name} <file.xapk>")
        sys.exit(1)

    xapk = Path(sys.argv[1]).resolve()

    if not xapk.is_file() or xapk.suffix != ".xapk":
        print(f"Error: '{xapk}' is not a valid .xapk file")
        sys.exit(1)

    output = Path.cwd() / (xapk.stem + "_frida.apk")

    try:
        Pipeline(xapk, output).execute()
    except Exception as exc:
        print(f"\n[FATAL] {exc}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
