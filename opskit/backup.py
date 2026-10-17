"""ZIP backup with a SHA-256 manifest and non-overwriting restore.

No ownership/ACL preservation: this is a file-content backup, not a system image.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path, PurePosixPath
import json
import os
import shutil
import stat
import tempfile
from zipfile import BadZipFile, ZIP_DEFLATED, ZipFile

CHUNK = 64 * 1024
MAX_FILES = 10000
MAX_BYTES = 1024 * 1024 * 1024


def safe_relative(name: str) -> str:
    if not isinstance(name, str) or not name or "\\" in name or ":" in name or "\x00" in name:
        raise ValueError("Unsafe archive path")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in name.split("/")):
        raise ValueError("Unsafe archive path")
    # Avoid Windows special device filenames when restoring a Linux archive on Windows.
    reserved = {"CON", "PRN", "AUX", "NUL"} | {f"{prefix}{n}" for prefix in ("COM", "LPT") for n in range(1, 10)}
    for part in path.parts:
        if part.endswith((".", " ")) or part.split(".")[0].upper() in reserved:
            raise ValueError("Non-portable archive path")
    return name


def create(source: Path, destination: Path, max_bytes: int = MAX_BYTES) -> int:
    source = source.resolve(strict=True)
    destination = destination.absolute()
    if not source.is_dir():
        raise ValueError("Source must be a directory")
    if destination.resolve().is_relative_to(source):
        raise ValueError("Backup must be outside the source directory")
    if destination.exists():
        raise FileExistsError("Destination already exists")
    files = []
    portable_paths = set()
    total = 0
    with tempfile.NamedTemporaryFile(dir=destination.parent, suffix=".zip", delete=False) as stream:
        temp = Path(stream.name)
    try:
        with ZipFile(temp, "w", compression=ZIP_DEFLATED) as archive:
            for path in sorted(source.rglob("*")):
                if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
                    raise ValueError("Symlinks and junctions are not supported")
                mode = path.stat().st_mode
                if stat.S_ISDIR(mode):
                    continue
                if not stat.S_ISREG(mode):
                    raise ValueError("Only regular files are supported")
                if len(files) >= MAX_FILES:
                    raise ValueError("Too many files")
                relative = safe_relative(path.relative_to(source).as_posix())
                if relative.casefold() in portable_paths:
                    raise ValueError("Case-colliding file paths are not portable")
                portable_paths.add(relative.casefold())
                digest, size = sha256(), 0
                with path.open("rb") as original, archive.open("files/" + relative, "w") as stored:
                    while chunk := original.read(CHUNK):
                        size += len(chunk)
                        total += len(chunk)
                        if total > max_bytes:
                            raise ValueError("Backup size limit exceeded")
                        digest.update(chunk)
                        stored.write(chunk)
                files.append({"path": relative, "size": size, "sha256": digest.hexdigest()})
            manifest = json.dumps({"format": 1, "files": files}, ensure_ascii=False, indent=2)
            if len(manifest.encode("utf-8")) > 1024 * 1024:
                raise ValueError("Manifest size limit exceeded")
            archive.writestr("manifest.json", manifest + "\n")
        # Exclusive creation prevents overwrites on filesystems without hard links.
        # A process crash while copying may leave an incomplete, detectable ZIP.
        with destination.open("xb") as output:
            try:
                with temp.open("rb") as original:
                    shutil.copyfileobj(original, output)
            except BaseException:
                output.close()
                destination.unlink(missing_ok=True)
                raise
        return len(files)
    finally:
        temp.unlink(missing_ok=True)


def validate_manifest(archive: ZipFile, max_bytes: int) -> list[dict]:
    infos = archive.infolist()
    names = [info.filename for info in infos]
    if len(infos) > MAX_FILES + 1 or len(set(names)) != len(names):
        raise ValueError("Duplicate or excessive archive members")
    manifest_info = archive.getinfo("manifest.json")
    if manifest_info.file_size > 1024 * 1024:
        raise ValueError("Manifest too large")
    manifest = json.loads(archive.read("manifest.json"))
    if not isinstance(manifest, dict) or manifest.get("format") != 1:
        raise ValueError("Unsupported manifest format")
    files = manifest.get("files")
    if not isinstance(files, list) or len(files) > MAX_FILES:
        raise ValueError("Invalid file list")
    expected = {"manifest.json"}
    portable_paths = set()
    total = 0
    for item in files:
        if not isinstance(item, dict):
            raise ValueError("Invalid manifest entry")
        name = safe_relative(item.get("path"))
        key = name.casefold()
        if key in portable_paths:
            raise ValueError("Duplicate or case-colliding file path")
        portable_paths.add(key)
        if type(item.get("size")) is not int or item["size"] < 0:
            raise ValueError("Invalid file size")
        digest = item.get("sha256")
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("Invalid SHA-256")
        total += item["size"]
        if total > max_bytes:
            raise ValueError("Archive size limit exceeded")
        member = "files/" + name
        expected.add(member)
        info = archive.getinfo(member)
        mode = info.external_attr >> 16
        if (stat.S_IFMT(mode) not in {0, stat.S_IFREG}) or info.file_size != item["size"]:
            raise ValueError("Invalid member type or size")
    if set(names) != expected:
        raise ValueError("Unexpected or missing archive member")
    return files


def copy_checked(archive: ZipFile, item: dict, output=None) -> None:
    digest, size = sha256(), 0
    with archive.open("files/" + item["path"]) as source:
        while chunk := source.read(CHUNK):
            size += len(chunk)
            if size > item["size"]:
                raise ValueError("Expanded size exceeds manifest")
            digest.update(chunk)
            if output is not None:
                output.write(chunk)
    if size != item["size"] or digest.hexdigest() != item["sha256"]:
        raise ValueError("Content checksum mismatch")


def verify(path: Path, max_bytes: int = MAX_BYTES) -> int:
    with ZipFile(path) as archive:
        files = validate_manifest(archive, max_bytes)
        for item in files:
            copy_checked(archive, item)
        return len(files)


def restore(path: Path, destination: Path, max_bytes: int = MAX_BYTES) -> int:
    destination = destination.absolute()
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("Restore destination must not exist")
    parent = destination.parent.resolve(strict=True)
    stage = Path(tempfile.mkdtemp(prefix="opskit-restore-", dir=parent))
    try:
        with ZipFile(path) as archive:
            files = validate_manifest(archive, max_bytes)
            for item in files:
                target = stage / item["path"]
                if not target.resolve().is_relative_to(stage.resolve()):
                    raise ValueError("Path escaped restore staging directory")
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("xb") as output:
                    copy_checked(archive, item, output)
        # Reserve the destination atomically. Never overwrite an existing directory.
        destination.mkdir()
        try:
            for child in stage.iterdir():
                child.rename(destination / child.name)
        except BaseException:
            # Retain any partial destination for inspection rather than deleting user data.
            raise
        return len(files)
    finally:
        # Only remove this operation's fresh staging directory under the verified parent.
        if stage.parent.resolve() == parent and stage.name.startswith("opskit-restore-"):
            shutil.rmtree(stage)
