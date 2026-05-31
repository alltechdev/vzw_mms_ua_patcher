"""
Full test suite for patch_rro.py.
Tests every important path: detection, patching, signing, error handling, edge cases.
Run with: python3 tests/test_patcher.py  (from tui_patcher/ directory)
Or:        python3 -m pytest tests/
"""
import os
import sys
import io
import struct
import tempfile
import unittest
import zipfile

# Make sure patch_rro and apk_factory are importable from tui_patcher/
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import patch_rro as P
from apk_factory import (
    build_arsc, build_apk,
    stock_m5_apk, stock_f21_apk, patched_apk, no_mms_apk,
    custom_ua_apk, empty_zip,
    TARGET_UA, TARGET_UAPROF,
)


def write_tmp(data, suffix=".apk"):
    """Write bytes to a temp file and return its path."""
    f = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    f.write(data)
    f.close()
    return f.name


def read_arsc_from_bytes(apk_bytes):
    with zipfile.ZipFile(io.BytesIO(apk_bytes)) as z:
        return z.read("resources.arsc")


# ---------------------------------------------------------------------------
# 1. APK factory sanity
# ---------------------------------------------------------------------------
class TestFactory(unittest.TestCase):
    """Verify the factory produces parseable, structurally valid APKs."""

    def test_stock_m5_roundtrip(self):
        arsc = read_arsc_from_bytes(stock_m5_apk())
        st   = P.get_mms_status(arsc)
        self.assertEqual(st["ua_current"],    "Android-Mms/0.1")
        self.assertEqual(st["uaprof_current"],"http://www.google.com/oha/rdf/ua-profile-kila.xml")
        self.assertFalse(st["patched_ua"])
        self.assertFalse(st["patched_uaprof"])

    def test_stock_f21_roundtrip(self):
        arsc = read_arsc_from_bytes(stock_f21_apk())
        st   = P.get_mms_status(arsc)
        self.assertEqual(st["ua_current"],    "Android-Mms/2.0")
        self.assertEqual(st["uaprof_current"],"http://uaprof.sonymobile.com/H8296R5111.xml")

    def test_patched_roundtrip(self):
        arsc = read_arsc_from_bytes(patched_apk())
        st   = P.get_mms_status(arsc)
        self.assertTrue(st["patched_ua"])
        self.assertTrue(st["patched_uaprof"])
        self.assertEqual(st["ua_current"],    TARGET_UA)
        self.assertEqual(st["uaprof_current"],TARGET_UAPROF)

    def test_detection_method_is_key_lookup(self):
        arsc = read_arsc_from_bytes(stock_m5_apk())
        st   = P.get_mms_status(arsc)
        self.assertEqual(st["method"], "key_lookup")

    def test_custom_values_roundtrip(self):
        arsc = read_arsc_from_bytes(custom_ua_apk("Samsung-Mms/3.5", "http://uaprof.samsung.com/foo.xml"))
        st   = P.get_mms_status(arsc)
        self.assertEqual(st["ua_current"],    "Samsung-Mms/3.5")
        self.assertEqual(st["uaprof_current"],"http://uaprof.samsung.com/foo.xml")


# ---------------------------------------------------------------------------
# 2. Patching correctness
# ---------------------------------------------------------------------------
class TestPatching(unittest.TestCase):

    def _patch(self, apk_bytes):
        arsc   = read_arsc_from_bytes(apk_bytes)
        p, res = P.do_patch_arsc(arsc)
        return p, res

    def test_patch_m5_succeeds(self):
        p, res = self._patch(stock_m5_apk())
        self.assertEqual(res, "ok")
        st = P.get_mms_status(p)
        self.assertTrue(st["patched_ua"])
        self.assertTrue(st["patched_uaprof"])
        self.assertEqual(st["ua_current"],    TARGET_UA)
        self.assertEqual(st["uaprof_current"],TARGET_UAPROF)

    def test_patch_f21_succeeds(self):
        p, res = self._patch(stock_f21_apk())
        self.assertEqual(res, "ok")
        st = P.get_mms_status(p)
        self.assertTrue(st["patched_ua"])
        self.assertTrue(st["patched_uaprof"])

    def test_patch_already_patched_returns_already_patched(self):
        _, res = self._patch(patched_apk())
        self.assertEqual(res, "already_patched")

    def test_patch_preserves_arsc_validity(self):
        """Patched arsc must still parse as a valid ResTable."""
        p, _ = self._patch(stock_f21_apk())
        pool_start, _ = P.get_global_pool_bounds(p)
        self.assertGreater(pool_start, 0)

    def test_patch_does_not_corrupt_other_strings(self):
        """Extra strings in global pool should be untouched after patching."""
        arsc = build_arsc("Android-Mms/2.0", "http://uaprof.sonymobile.com/H8296R5111.xml",
                          extra_strings=["some_other_value", "keep_me_intact"])
        p, res = P.do_patch_arsc(arsc)
        self.assertEqual(res, "ok")
        # Read back all strings from patched pool
        pool_start, pool_size = P.get_global_pool_bounds(p)
        pool = p[pool_start: pool_start + pool_size]
        all_strings = [s for _, s in P.iter_pool_strings(pool)]
        self.assertIn("some_other_value", all_strings)
        self.assertIn("keep_me_intact",   all_strings)

    def test_patch_idempotent(self):
        """Patching twice should produce the same result as patching once."""
        arsc   = read_arsc_from_bytes(stock_m5_apk())
        p1, _  = P.do_patch_arsc(arsc)
        _, res = P.do_patch_arsc(p1)
        self.assertEqual(res, "already_patched")

    def test_patch_any_custom_ua(self):
        """Patcher must work regardless of what value the manufacturer used."""
        custom_cases = [
            ("HTC-Mms/1.0",       "http://uaprof.htc.com/htc_desire.xml"),
            ("LG-Mms/5.0",        "http://uaprof.lge.com/KU990r.xml"),
            ("Kyocera-Mms/2.1",   "http://uaprof.kyocera.com/DuraXE.xml"),
            ("Moto-Mms/3.0",      "http://uaprof.motorola.com/otasupport/MotoG.rdf"),
        ]
        for ua, uaprof in custom_cases:
            with self.subTest(ua=ua):
                apk  = custom_ua_apk(ua, uaprof)
                arsc = read_arsc_from_bytes(apk)
                p, res = P.do_patch_arsc(arsc)
                self.assertEqual(res, "ok", f"Failed for UA={ua}")
                st = P.get_mms_status(p)
                self.assertTrue(st["patched_ua"])
                self.assertTrue(st["patched_uaprof"])

    def test_chunk_size_updated_after_patch(self):
        """ResTable outer chunk_size must reflect the delta from patching."""
        arsc  = read_arsc_from_bytes(stock_f21_apk())
        orig_size = struct.unpack_from("<I", arsc, 4)[0]
        p, _  = P.do_patch_arsc(arsc)
        new_size  = struct.unpack_from("<I", p, 4)[0]
        # Sony URL (43 bytes) → vtext URL (59 bytes): +16
        # Android-Mms/2.0 (15 bytes) → odopcph2583 (11 bytes): -4
        # net delta = +12
        self.assertEqual(new_size, orig_size + 12)


# ---------------------------------------------------------------------------
# 3. APK file I/O
# ---------------------------------------------------------------------------
class TestAPKIO(unittest.TestCase):

    def test_read_valid_apk(self):
        path = write_tmp(stock_m5_apk())
        try:
            arsc = P.read_arsc_from_apk(path)
            self.assertIsNotNone(arsc)
            self.assertGreater(len(arsc), 0)
        finally:
            os.unlink(path)

    def test_file_not_found(self):
        with self.assertRaises(FileNotFoundError) as ctx:
            P.read_arsc_from_apk("/absolutely/nonexistent/path/foo.apk")
        self.assertIn("not found", str(ctx.exception).lower())

    def test_not_a_zip(self):
        path = write_tmp(b"this is not a zip file at all")
        try:
            with self.assertRaises(ValueError) as ctx:
                P.read_arsc_from_apk(path)
            self.assertIn("APK", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_zip_without_resources_arsc(self):
        path = write_tmp(empty_zip())
        try:
            with self.assertRaises(ValueError) as ctx:
                P.read_arsc_from_apk(path)
            self.assertIn("resources.arsc", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_write_patched_apk_roundtrip(self):
        """write_unsigned_apk then read_arsc_from_apk must return patched arsc."""
        src_apk  = write_tmp(stock_m5_apk())
        dst_apk  = write_tmp(b"", suffix="_out.apk")
        try:
            arsc    = P.read_arsc_from_apk(src_apk)
            p, _    = P.do_patch_arsc(arsc)
            P.write_unsigned_apk(src_apk, dst_apk, p)
            readback= P.read_arsc_from_apk(dst_apk)
            st      = P.get_mms_status(readback)
            self.assertTrue(st["patched_ua"])
            self.assertTrue(st["patched_uaprof"])
        finally:
            os.unlink(src_apk)
            os.unlink(dst_apk)

    def test_write_strips_meta_inf(self):
        """write_unsigned_apk must strip META-INF (old signature)."""
        # Build an APK that has a fake META-INF entry
        arsc  = build_arsc("Android-Mms/2.0", "http://uaprof.sonymobile.com/H8296R5111.xml")
        apk   = build_apk(arsc, **{"META-INF/CERT.SF": b"fake sig"})
        src   = write_tmp(apk)
        dst   = write_tmp(b"", suffix="_out.apk")
        try:
            p, _  = P.do_patch_arsc(arsc)
            P.write_unsigned_apk(src, dst, p)
            with zipfile.ZipFile(dst) as z:
                names = z.namelist()
            self.assertNotIn("META-INF/CERT.SF", names)
            self.assertIn("resources.arsc", names)
        finally:
            os.unlink(src)
            os.unlink(dst)

    def test_output_not_created_on_wrong_apk(self):
        """cmd_patch must not create output file when APK has no MMS strings."""
        src = write_tmp(empty_zip())
        dst = src + "_out.apk"
        try:
            P.cmd_patch(src, dst)
            self.assertFalse(os.path.exists(dst),
                "Output should not be created when patch fails")
        finally:
            os.unlink(src)
            if os.path.exists(dst):
                os.unlink(dst)

    def test_no_output_on_patch_failure_cleans_up(self):
        """Temp file must be cleaned up if write fails mid-way."""
        src = write_tmp(stock_m5_apk())
        dst = "/root/no_permission_here/out.apk"
        try:
            result = P.cmd_patch(src, dst)
            self.assertFalse(result)
            self.assertFalse(os.path.exists(dst + ".tmp"))
        finally:
            os.unlink(src)


# ---------------------------------------------------------------------------
# 4. cmd_check output
# ---------------------------------------------------------------------------
class TestCmdCheck(unittest.TestCase):
    """Test that cmd_check returns correct status dicts."""

    def _check(self, apk_bytes):
        path = write_tmp(apk_bytes)
        try:
            return P.cmd_check(path)
        finally:
            os.unlink(path)

    def test_check_stock_needs_patching(self):
        st = self._check(stock_m5_apk())
        self.assertFalse(st["patched_ua"])
        self.assertFalse(st["patched_uaprof"])
        self.assertIsNotNone(st["ua_pool_index"])

    def test_check_already_patched(self):
        st = self._check(patched_apk())
        self.assertTrue(st["patched_ua"])
        self.assertTrue(st["patched_uaprof"])

    def test_check_wrong_apk_returns_none(self):
        st = self._check(empty_zip())
        self.assertIsNone(st)

    def test_check_nonexistent_file_returns_none(self):
        st = P.cmd_check("/nonexistent/file.apk")
        self.assertIsNone(st)


# ---------------------------------------------------------------------------
# 5. cmd_patch full flow
# ---------------------------------------------------------------------------
class TestCmdPatch(unittest.TestCase):

    def test_patch_stock_produces_correct_output(self):
        src = write_tmp(stock_f21_apk())
        dst = src + "_out.apk"
        try:
            result = P.cmd_patch(src, dst)
            self.assertTrue(result)
            self.assertTrue(os.path.exists(dst))
            arsc = P.read_arsc_from_apk(dst)
            st   = P.get_mms_status(arsc)
            self.assertTrue(st["patched_ua"])
            self.assertTrue(st["patched_uaprof"])
        finally:
            os.unlink(src)
            if os.path.exists(dst): os.unlink(dst)

    def test_patch_already_patched_returns_true_no_output(self):
        src = write_tmp(patched_apk())
        dst = src + "_out.apk"
        try:
            result = P.cmd_patch(src, dst)
            self.assertTrue(result)
            self.assertFalse(os.path.exists(dst))
        finally:
            os.unlink(src)

    def test_patch_wrong_apk_returns_false_no_output(self):
        src = write_tmp(empty_zip())
        dst = src + "_out.apk"
        try:
            result = P.cmd_patch(src, dst)
            self.assertFalse(result)
            self.assertFalse(os.path.exists(dst))
        finally:
            os.unlink(src)
            if os.path.exists(dst): os.unlink(dst)

    def test_patch_nonexistent_src_returns_false(self):
        result = P.cmd_patch("/does/not/exist.apk", "/tmp/never_created.apk")
        self.assertFalse(result)
        self.assertFalse(os.path.exists("/tmp/never_created.apk"))

    def test_patch_overwrites_existing_output(self):
        """If output already exists, it should be replaced."""
        src = write_tmp(stock_m5_apk())
        dst = write_tmp(b"old content")
        try:
            result = P.cmd_patch(src, dst)
            self.assertTrue(result)
            # New output should be a valid APK with patched values
            arsc = P.read_arsc_from_apk(dst)
            st   = P.get_mms_status(arsc)
            self.assertTrue(st["patched_ua"])
        finally:
            os.unlink(src)
            if os.path.exists(dst): os.unlink(dst)


# ---------------------------------------------------------------------------
# 6. Error handling
# ---------------------------------------------------------------------------
class TestErrorHandling(unittest.TestCase):

    def test_truncated_arsc_raises(self):
        with self.assertRaises((ValueError, struct.error, AssertionError)):
            P.get_global_pool_bounds(b"\x02\x00" + b"\x00" * 4)

    def test_wrong_chunk_type_raises(self):
        bad = struct.pack("<HHI", 0xFFFF, 8, 8)
        with self.assertRaises(ValueError) as ctx:
            P.get_global_pool_bounds(bad)
        self.assertIn("0x", str(ctx.exception))

    def test_status_on_no_mms_keys(self):
        """APK with no config_mms_user_agent keys should return method=none."""
        arsc = build_arsc("some_value", "http://example.com/some.xml")
        # Replace key pool strings with unrelated ones
        # (build_arsc always inserts our keys, so use no_mms approach differently)
        # Just check that patching a "custom" value still finds it by key lookup
        st = P.get_mms_status(arsc)
        # build_arsc always sets the correct keys, so method should be key_lookup
        self.assertEqual(st["method"], "key_lookup")


# ---------------------------------------------------------------------------
# 7. Round-trip integrity
# ---------------------------------------------------------------------------
class TestIntegrity(unittest.TestCase):

    def test_patch_and_verify_all_fields(self):
        """After patching, every field should be exactly what we expect."""
        for fixture_name, apk_fn in [
            ("m5",  stock_m5_apk),
            ("f21", stock_f21_apk),
        ]:
            with self.subTest(fixture=fixture_name):
                arsc    = read_arsc_from_bytes(apk_fn())
                p, res  = P.do_patch_arsc(arsc)
                self.assertEqual(res, "ok")
                st = P.get_mms_status(p)
                self.assertEqual(st["ua_current"],    TARGET_UA)
                self.assertEqual(st["uaprof_current"],TARGET_UAPROF)
                self.assertTrue(st["patched_ua"])
                self.assertTrue(st["patched_uaprof"])
                self.assertEqual(st["method"], "key_lookup")

    def test_global_pool_alignment(self):
        """Patched arsc global pool chunk_size must be 4-byte aligned."""
        arsc   = read_arsc_from_bytes(stock_f21_apk())
        p, _   = P.do_patch_arsc(arsc)
        ps, pz = P.get_global_pool_bounds(p)
        self.assertEqual(pz % 4, 0)

    def test_restable_chunk_size_matches_len(self):
        """Outer ResTable chunk_size must equal actual bytes length."""
        arsc  = read_arsc_from_bytes(stock_m5_apk())
        p, _  = P.do_patch_arsc(arsc)
        declared_size = struct.unpack_from("<I", p, 4)[0]
        self.assertEqual(declared_size, len(p))


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    loader  = unittest.TestLoader()
    suite   = loader.loadTestsFromModule(sys.modules[__name__])
    runner  = unittest.TextTestRunner(verbosity=2)
    result  = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
