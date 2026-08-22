import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import verify

class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.dep = self.root / "deps" / "one"
        self.dep.mkdir(parents=True)
        (self.dep / "identity.txt").write_bytes(b"identity\n")
        self.digest = __import__("hashlib").sha256(b"identity\n").hexdigest()

    def tearDown(self):
        self.temp.cleanup()

    def manifest(self):
        return {"schema_version":1,"dependencies":[{"name":"one","local_path":"deps/one","version":None,"revision":None,"license_path":None,"required_files":[{"path":"identity.txt","sha256":self.digest}]}]}

    def write_manifest(self, value):
        path = self.root / "manifest.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_valid_manifest(self):
        self.assertEqual(verify.verify(self.root, self.manifest()), 1)

    def test_missing_required_file(self):
        value = self.manifest()
        value["dependencies"][0]["required_files"][0]["path"] = "missing.txt"
        with self.assertRaisesRegex(verify.VerificationError, "required file is missing"):
            verify.verify(self.root, value)

    def test_hash_mismatch(self):
        value = self.manifest()
        value["dependencies"][0]["required_files"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(verify.VerificationError, "SHA-256 mismatch"):
            verify.verify(self.root, value)

    def test_rejects_duplicates_and_escape(self):
        value = self.manifest()
        value["dependencies"].append(dict(value["dependencies"][0]))
        with self.assertRaisesRegex(verify.VerificationError, "duplicate dependency name"):
            verify.verify(self.root, value)
        value = self.manifest()
        value["dependencies"][0]["local_path"] = "../outside"
        with self.assertRaisesRegex(verify.VerificationError, "escapes repository root"):
            verify.verify(self.root, value)

    def test_cli_help_and_json(self):
        manifest_path = self.write_manifest(self.manifest())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as exit_info:
                verify.main(["--help"])
        self.assertEqual(exit_info.exception.code, 0)
        self.assertIn("--manifest", output.getvalue())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = verify.main(["--root", str(self.root), "--manifest", str(manifest_path), "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "ok")

    def test_malformed_manifest(self):
        path = self.root / "bad.json"
        path.write_text("{", encoding="utf-8")
        with self.assertRaises(verify.VerificationError):
            verify.load_manifest(path)

if __name__ == "__main__":
    unittest.main()
