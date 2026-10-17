from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZipFile
import json
import unittest

from opskit import backup


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "config.txt").write_text("Hello\nПривет\n", encoding="utf-8")
        (self.source / "nested").mkdir()
        (self.source / "nested" / "empty.bin").write_bytes(b"")
        self.archive = self.root / "backup.zip"

    def tearDown(self):
        self.tmp.cleanup()

    def malicious(self, name, content=b"demo", digest=None, extras=False):
        entry = {"path": name, "size": len(content), "sha256": digest or sha256(content).hexdigest()}
        with ZipFile(self.archive, "w") as archive:
            archive.writestr("manifest.json", json.dumps({"format": 1, "files": [entry]}))
            archive.writestr("files/" + name, content)
            if extras:
                archive.writestr("extra.txt", "unexpected")

    def test_round_trip_and_empty_file(self):
        self.assertEqual(backup.create(self.source, self.archive), 2)
        self.assertEqual(backup.verify(self.archive), 2)
        target = self.root / "restored"
        self.assertEqual(backup.restore(self.archive, target), 2)
        self.assertEqual((target / "config.txt").read_bytes(), (self.source / "config.txt").read_bytes())
        self.assertEqual((target / "nested/empty.bin").read_bytes(), b"")

    def test_no_overwrite_of_backup_or_restore(self):
        backup.create(self.source, self.archive)
        original = self.archive.read_bytes()
        with self.assertRaises(FileExistsError):
            backup.create(self.source, self.archive)
        self.assertEqual(self.archive.read_bytes(), original)
        with self.assertRaises(FileExistsError):
            backup.restore(self.archive, self.source)

    def test_archive_inside_source_is_rejected(self):
        with self.assertRaises(ValueError):
            backup.create(self.source, self.source / "backup.zip")

    def test_checksum_corruption_is_rejected_before_restore(self):
        self.malicious("file.txt", digest="0" * 64)
        target = self.root / "restored"
        with self.assertRaises(ValueError):
            backup.verify(self.archive)
        with self.assertRaises(ValueError):
            backup.restore(self.archive, target)
        self.assertFalse(target.exists())
        self.assertFalse(list(self.root.glob("opskit-restore-*")))

    def test_path_traversal_and_windows_paths(self):
        for name in ["../escape", "/absolute", "C:/escape", "a\\..\\escape", "a/./b", "CON.txt", "a/../b"]:
            with self.subTest(name=name):
                self.malicious(name)
                with self.assertRaises(ValueError):
                    backup.restore(self.archive, self.root / "restored")
        self.assertFalse((self.root / "escape").exists())

    def test_extra_entries_and_size_limits(self):
        self.malicious("file.txt", extras=True)
        with self.assertRaises(ValueError):
            backup.verify(self.archive)
        self.malicious("file.txt", content=b"12345")
        with self.assertRaises(ValueError):
            backup.verify(self.archive, max_bytes=4)
        self.archive.unlink()
        with self.assertRaises(ValueError):
            backup.create(self.source, self.archive, max_bytes=1)
        self.assertFalse(self.archive.exists())

    def test_safe_relative_rejects_case_independent_device_names(self):
        for name in ["nul", "a/LpT1.txt", "file.", "file ", "a//b"]:
            with self.assertRaises(ValueError):
                backup.safe_relative(name)
