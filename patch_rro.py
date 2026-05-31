#!/usr/bin/env python3
"""
Verizon MMS fix - patches User-Agent and UAProf URL in Android framework overlay APK.

Usage:
  python3 patch_rro.py                  # TUI
  python3 patch_rro.py check <apk>      # inspect APK
  python3 patch_rro.py patch <src> <out># patch only (unsigned)
"""
import re
import struct
import zipfile
import subprocess
import shutil
import sys
import os

# ---
# Target values  (OnePlus 12 on Verizon - 2592x1944 / 1.2 MB)
# ---
TARGET_UA     = "odopcph2583"
TARGET_UAPROF = "http://uaprof.vtext.com/OnePlus/odopcph2583/odopcph2583.xml"

KEY_UA     = "config_mms_user_agent"
KEY_UAPROF = "config_mms_user_agent_profile_url"

UA_RE     = re.compile(r'^[\w][\w.\-]*/[\d.]+$')
UAPROF_RE = re.compile(r'^https?://.*(?:uaprof|ua-profile)', re.IGNORECASE)

SCRIPT_DIR      = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR        = os.path.join(SCRIPT_DIR, "keys")
TESTKEY_PK8     = os.path.join(KEYS_DIR, "testkey.pk8")
TESTKEY_CERT    = os.path.join(KEYS_DIR, "testkey.x509.pem")
BUNDLED_SIGNER  = os.path.join(SCRIPT_DIR, "bin", "apksigner.jar")

# ---
# ResTable constants
# ---
CHUNK_TABLE   = 0x0002
CHUNK_POOL    = 0x0001
CHUNK_PACKAGE = 0x0200
CHUNK_TYPE    = 0x0201
FLAG_COMPLEX  = 0x0001
TYPE_STRING   = 0x03
NO_ENTRY      = 0xFFFFFFFF
UTF8_FLAG     = 0x100

# ---
# Terminal color helpers
# ---
def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text

def green(t):  return _c("32", t)
def red(t):    return _c("31", t)
def yellow(t): return _c("33", t)
def bold(t):   return _c("1",  t)
def dim(t):    return _c("2",  t)

def hr():
    print(dim("  " + "─" * 50))

# ---
# Input wrapper - handles EOF (piped input / Ctrl-D) cleanly
# ---
def _input(prompt):
    try:
        return input(prompt)
    except EOFError:
        print()
        sys.exit(0)

# ---
# Varint
# ---
def read_varint(data, pos):
    b = data[pos]
    if b & 0x80:
        return ((b & 0x7F) << 8) | data[pos + 1], 2
    return b, 1

def write_varint(val):
    if val >= 0x80:
        return bytes([(val >> 8) | 0x80, val & 0xFF])
    return bytes([val])

# ---
# String pool traversal
# ---
def iter_pool_strings(pool):
    if len(pool) < 28:
        return
    chunk_type, header_size = struct.unpack_from("<HH", pool, 0)
    if chunk_type != CHUNK_POOL:
        return
    string_count, _, flags, strings_start, _ = struct.unpack_from("<IIIII", pool, 8)
    if not (flags & UTF8_FLAG):
        return
    for i in range(string_count):
        op = header_size + i * 4
        if op + 4 > len(pool):
            break
        off = struct.unpack_from("<I", pool, op)[0]
        pos = strings_start + off
        if pos + 4 > len(pool):
            continue
        _, cw = read_varint(pool, pos)
        if pos + cw + 2 > len(pool):
            continue
        byte_len, bw = read_varint(pool, pos + cw)
        end = pos + cw + bw + byte_len
        if end > len(pool):
            continue
        raw = bytes(pool[pos + cw + bw: end])
        try:
            yield i, raw.decode("utf-8")
        except UnicodeDecodeError:
            pass

def get_pool_string(pool, index):
    for i, s in iter_pool_strings(pool):
        if i == index:
            return s
    return None

# ---
# ResTable navigation
# ---
def get_global_pool_bounds(arsc):
    if len(arsc) < 8:
        raise ValueError("File too small to be a valid resources.arsc.")
    ctype, hdr_size = struct.unpack_from("<HH", arsc, 0)
    if ctype != CHUNK_TABLE:
        raise ValueError(
            "Not a valid resources.arsc.\n"
            "  Expected chunk type 0x0002, got 0x{:04x}.\n"
            "  Make sure you selected:\n"
            "  framework-res__auto_generated_rro_product.apk".format(ctype)
        )
    ps = hdr_size
    if ps + 8 > len(arsc):
        raise ValueError("resources.arsc is truncated.")
    return ps, struct.unpack_from("<I", arsc, ps + 4)[0]


def find_mms_global_indices(arsc):
    pool_start, pool_size = get_global_pool_bounds(arsc)
    pkg_start = pool_start + pool_size

    if pkg_start + 8 > len(arsc):
        return {}
    if struct.unpack_from("<H", arsc, pkg_start)[0] != CHUNK_PACKAGE:
        return {}

    pkg_hdr  = struct.unpack_from("<H", arsc, pkg_start + 2)[0]
    pkg_size = struct.unpack_from("<I", arsc, pkg_start + 4)[0]

    if pkg_start + 280 > len(arsc):
        return {}
    ks_off  = struct.unpack_from("<I", arsc, pkg_start + 276)[0]
    kp_abs  = pkg_start + ks_off
    if kp_abs + 8 > len(arsc):
        return {}
    kp_size = struct.unpack_from("<I", arsc, kp_abs + 4)[0]
    key_pool = arsc[kp_abs: kp_abs + kp_size]

    key_idx_map = {}
    for idx, s in iter_pool_strings(key_pool):
        if s in (KEY_UA, KEY_UAPROF):
            key_idx_map[s] = idx

    if not key_idx_map:
        return {}

    result = {}
    pos     = pkg_start + pkg_hdr
    pkg_end = pkg_start + pkg_size

    while pos < pkg_end and len(result) < 2:
        if pos + 8 > len(arsc):
            break
        ctype = struct.unpack_from("<H", arsc, pos)[0]
        csize = struct.unpack_from("<I", arsc, pos + 4)[0]
        if csize == 0:
            break
        if ctype == CHUNK_TYPE:
            thdr   = struct.unpack_from("<H", arsc, pos + 2)[0]
            ecount = struct.unpack_from("<I", arsc, pos + 12)[0]
            estart = struct.unpack_from("<I", arsc, pos + 16)[0]
            for i in range(ecount):
                op = pos + thdr + i * 4
                if op + 4 > len(arsc):
                    break
                eoff = struct.unpack_from("<I", arsc, op)[0]
                if eoff == NO_ENTRY:
                    continue
                ea = pos + estart + eoff
                if ea + 8 > len(arsc):
                    continue
                esz    = struct.unpack_from("<H", arsc, ea)[0]
                eflags = struct.unpack_from("<H", arsc, ea + 2)[0]
                ekey   = struct.unpack_from("<I", arsc, ea + 4)[0]
                if eflags & FLAG_COMPLEX:
                    continue
                va = ea + esz
                if va + 8 > len(arsc):
                    continue
                vtype = arsc[va + 3] if isinstance(arsc, (bytes, bytearray)) \
                        else struct.unpack_from("B", arsc, va + 3)[0]
                if vtype != TYPE_STRING:
                    continue
                vdata = struct.unpack_from("<I", arsc, va + 4)[0]
                for kname, kidx in key_idx_map.items():
                    if ekey == kidx and kname not in result:
                        result[kname] = vdata
        pos += csize

    return result


# ---
# String pool patching
# ---
def patch_string_pool_at_index(pool, index, new_str):
    new_b = new_str.encode("utf-8")
    _, hdr_size, chunk_size = struct.unpack_from("<HHI", pool, 0)
    sc, _, _, ss, _ = struct.unpack_from("<IIIII", pool, 8)
    os_ = hdr_size

    off = struct.unpack_from("<I", pool, os_ + index * 4)[0]
    pos = ss + off
    _, cw = read_varint(pool, pos)
    bl, bw = read_varint(pool, pos + cw)

    old_entry   = cw + bw + bl + 1
    replacement = write_varint(len(new_str)) + write_varint(len(new_b)) + new_b + b"\x00"
    delta       = len(replacement) - old_entry

    pool[pos: pos + old_entry] = replacement

    old_end = off + old_entry
    for j in range(sc):
        jp = os_ + j * 4
        jo = struct.unpack_from("<I", pool, jp)[0]
        if jo >= old_end:
            struct.pack_into("<I", pool, jp, jo + delta)

    ncs = chunk_size + delta
    pad = (4 - (ncs % 4)) % 4
    if pad:
        pool.extend(b"\x00" * pad)
        ncs += pad
    struct.pack_into("<I", pool, 4, ncs)
    return pool, ncs - chunk_size


# ---
# Status and patching
# ---
def get_mms_status(arsc):
    ps, pz = get_global_pool_bounds(arsc)
    gp     = arsc[ps: ps + pz]

    p_ua, p_up     = False, False
    ua_idx, up_idx = None, None
    ua_val, up_val = None, None
    method         = "none"

    indices = find_mms_global_indices(arsc)

    if KEY_UA in indices or KEY_UAPROF in indices:
        method = "key_lookup"
        if KEY_UA in indices:
            ua_idx = indices[KEY_UA]
            ua_val = get_pool_string(gp, ua_idx)
            if ua_val == TARGET_UA:
                p_ua = True
        if KEY_UAPROF in indices:
            up_idx = indices[KEY_UAPROF]
            up_val = get_pool_string(gp, up_idx)
            if up_val == TARGET_UAPROF:
                p_up = True
    else:
        for idx, s in iter_pool_strings(gp):
            if s == TARGET_UA:
                p_ua, ua_idx, ua_val, method = True, idx, s, "pattern_scan"
            elif s == TARGET_UAPROF:
                p_up, up_idx, up_val, method = True, idx, s, "pattern_scan"
            elif ua_idx is None and UA_RE.match(s):
                ua_idx, ua_val, method = idx, s, "pattern_scan"
            elif up_idx is None and UAPROF_RE.match(s):
                up_idx, up_val, method = idx, s, "pattern_scan"

    return {
        "method":            method,
        "ua_current":        ua_val,
        "uaprof_current":    up_val,
        "ua_pool_index":     ua_idx,
        "uaprof_pool_index": up_idx,
        "patched_ua":        p_ua,
        "patched_uaprof":    p_up,
    }


def do_patch_arsc(arsc):
    st = get_mms_status(arsc)

    if st["patched_ua"] and st["patched_uaprof"]:
        return None, "already_patched"

    if st["ua_pool_index"] is None and st["uaprof_pool_index"] is None:
        return None, (
            "No MMS strings detected - probably the wrong APK.\n"
            "  Expected: framework-res__auto_generated_rro_product.apk\n"
            "  Location: /product/overlay/ inside the device firmware."
        )

    missing = []
    if st["ua_pool_index"] is None and not st["patched_ua"]:
        missing.append(f"  - {KEY_UA}")
    if st["uaprof_pool_index"] is None and not st["patched_uaprof"]:
        missing.append(f"  - {KEY_UAPROF}")
    if missing:
        return None, (
            "Some MMS strings could not be found:\n" + "\n".join(missing) + "\n"
            "  Run 'check' for details."
        )

    data  = bytearray(arsc)
    _, hs, rs = struct.unpack_from("<HHI", data, 0)
    ps, ops   = get_global_pool_bounds(data)
    pool      = bytearray(data[ps: ps + ops])
    td        = 0

    if not st["patched_ua"] and st["ua_pool_index"] is not None:
        pool, d = patch_string_pool_at_index(pool, st["ua_pool_index"], TARGET_UA)
        td += d
    if not st["patched_uaprof"] and st["uaprof_pool_index"] is not None:
        pool, d = patch_string_pool_at_index(pool, st["uaprof_pool_index"], TARGET_UAPROF)
        td += d

    data[ps: ps + ops] = pool
    struct.pack_into("<I", data, 4, rs + td)
    return bytes(data), "ok"


# ---
# APK I/O
# ---
def read_arsc_from_apk(apk_path):
    if not os.path.exists(apk_path):
        raise FileNotFoundError(
            f"File not found: {apk_path}\n"
            "  Check the path and try again."
        )
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            if "resources.arsc" not in z.namelist():
                raise ValueError(
                    "No resources.arsc in this file.\n"
                    "  Expected: framework-res__auto_generated_rro_product.apk"
                )
            return z.read("resources.arsc")
    except zipfile.BadZipFile:
        raise ValueError(
            f"Not a valid APK/ZIP: {apk_path}\n"
            "  Only .apk files are supported."
        )


def write_unsigned_apk(src_apk, dst_apk, patched_arsc):
    tmp = dst_apk + ".tmp"
    try:
        with zipfile.ZipFile(src_apk, "r") as zin, \
             zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_STORED) as zout:
            for item in zin.infolist():
                if item.filename == "resources.arsc":
                    zout.writestr(item, patched_arsc)
                elif item.filename.startswith("META-INF/"):
                    pass
                else:
                    zout.writestr(item, zin.read(item.filename))
        os.replace(tmp, dst_apk)
    except Exception:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


# ---
# Signing
# ---
def _apksigner_cmd():
    """Return the apksigner command: bundled JAR (preferred) or system binary."""
    if os.path.exists(BUNDLED_SIGNER) and shutil.which("java"):
        return ["java", "-jar", BUNDLED_SIGNER]
    if shutil.which("apksigner"):
        return ["apksigner"]
    raise RuntimeError(
        "Signing requires Java to use the bundled apksigner.jar.\n"
        "  Install Java: sudo apt install default-jre\n"
        "  Then try again."
    )


def sign_apk(unsigned_apk, signed_apk, pk8, cert):
    if not os.path.exists(pk8):
        raise FileNotFoundError(f"Private key not found: {pk8}")
    if not os.path.exists(cert):
        raise FileNotFoundError(f"Certificate not found: {cert}")
    cmd = _apksigner_cmd() + ["sign",
                               "--key", pk8, "--cert", cert,
                               "--min-sdk-version", "23",
                               "--out", signed_apk, unsigned_apk]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"apksigner failed:\n{result.stderr.strip()}")


def verify_signing(apk_path):
    """Return (signer_dn, sha1) or (None, None) if unavailable."""
    try:
        cmd = _apksigner_cmd()
    except RuntimeError:
        return None, None
    result = subprocess.run(
        cmd + ["verify", "--print-certs", apk_path],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        return None, None
    dn, sha1 = None, None
    for line in result.stdout.splitlines():
        if "certificate DN:" in line:
            dn = line.split("certificate DN:")[-1].strip()
        if "certificate SHA-1 digest:" in line:
            sha1 = line.split("SHA-1 digest:")[-1].strip()
    return dn, sha1


# ---
# Commands
# ---
def cmd_check(apk_path):
    print(f"\n{bold('Checking:')} {apk_path}")
    try:
        arsc   = read_arsc_from_apk(apk_path)
        status = get_mms_status(arsc)
    except Exception as e:
        print(f"\n  {red('ERROR:')} {e}")
        return None

    mtag = {
        "key_lookup":   green("resource name lookup  ← most reliable"),
        "pattern_scan": yellow("pattern scan (fallback)"),
        "none":         red("not found"),
    }.get(status["method"], status["method"])

    hr()
    print(f"  {bold('Detection :')} {mtag}")
    hr()

    ua  = status["ua_current"]    or red("(not detected)")
    uap = status["uaprof_current"] or red("(not detected)")

    print(f"  {bold('User-Agent')}  : {ua}")
    if status["patched_ua"]:
        print(f"                {green('✓ Already patched')}")
    elif status["ua_pool_index"] is not None:
        print(f"                {yellow('✗ Needs patching')}")
    else:
        print(f"                {red('? Not detected')}")

    print(f"\n  {bold('UAProf URL')}  : {uap}")
    if status["patched_uaprof"]:
        print(f"                {green('✓ Already patched')}")
    elif status["uaprof_pool_index"] is not None:
        print(f"                {yellow('✗ Needs patching')}")
    else:
        print(f"                {red('? Not detected')}")

    if status["method"] == "none":
        print(
            f"\n  {yellow('NOTE:')} No MMS strings found - this is likely the wrong APK.\n"
            "  Expected: framework-res__auto_generated_rro_product.apk\n"
            "  Location in firmware: /product/overlay/"
        )
    elif status["method"] == "pattern_scan":
        print(
            f"\n  {yellow('NOTE:')} Resource names not found - using pattern detection.\n"
            "  Verify the output before flashing."
        )

    hr()
    return status


def cmd_patch(src_apk, dst_apk, pk8=None, cert=None, sign_mode=None):
    print(f"\n  {bold('Source :')} {src_apk}")
    unsigned = dst_apk if sign_mode is None else dst_apk + ".unsigned.apk"
    print(f"  {bold('Output :')} {dst_apk}")
    if sign_mode:
        print(f"  {bold('Signing :')} {'AOSP testkey' if sign_mode == 'testkey' else 'custom key'}")

    try:
        arsc = read_arsc_from_apk(src_apk)
    except Exception as e:
        print(f"\n  {red('ERROR:')} {e}")
        return False

    st = get_mms_status(arsc)
    mtag = {
        "key_lookup":   green("key name lookup"),
        "pattern_scan": yellow("pattern scan"),
        "none":         red("none"),
    }.get(st["method"], st["method"])

    hr()
    print(f"  Detection : {mtag}")
    if not st["patched_ua"] and st["ua_pool_index"] is not None:
        print(f"  UA found  : {st['ua_current']}  {yellow(chr(8594))}  {TARGET_UA}")
    if not st["patched_uaprof"] and st["uaprof_pool_index"] is not None:
        print(f"  URL found : {st['uaprof_current']}")
        print(f"            {yellow(chr(8594))}  {TARGET_UAPROF}")

    patched_bytes, result = do_patch_arsc(arsc)

    if result == "already_patched":
        print(f"\n  {green('Already fully patched - nothing to do.')}")
        return True

    if result != "ok":
        print(f"\n  {red('ERROR:')} {result}")
        return False

    try:
        write_unsigned_apk(src_apk, unsigned, patched_bytes)
    except Exception as e:
        print(f"\n  {red('ERROR writing output:')} {e}")
        return False

    check = get_mms_status(patched_bytes)
    ok_ua  = check["patched_ua"]
    ok_uap = check["patched_uaprof"]
    print(f"\n  User-Agent : {green(chr(10003)+' Patched') if ok_ua  else red(chr(10007)+' FAILED')}")
    print(f"  UAProf URL : {green(chr(10003)+' Patched') if ok_uap else red(chr(10007)+' FAILED')}")

    if not (ok_ua and ok_uap):
        print(f"\n  {red('Patch verification failed. Deleting output.')}")
        for f in (unsigned, dst_apk):
            if os.path.exists(f):
                os.remove(f)
        return False

    if sign_mode:
        k = TESTKEY_PK8  if sign_mode == "testkey" else pk8
        c = TESTKEY_CERT if sign_mode == "testkey" else cert
        print(f"\n  Signing...")
        try:
            sign_apk(unsigned, dst_apk, k, c)
            if unsigned != dst_apk and os.path.exists(unsigned):
                os.remove(unsigned)
            dn, sha1 = verify_signing(dst_apk)
            if sha1:
                print(f"  {green(chr(10003)+' Signed')}")
                print(f"    Cert : {dn}")
                print(f"    SHA1 : {sha1}")
            else:
                print(f"  {green(chr(10003)+' Signed')} (verify unavailable)")
        except Exception as e:
            print(f"\n  {red('Signing ERROR:')} {e}")
            print(f"  {yellow('Unsigned output kept at:')} {unsigned}")
            return False
    else:
        print(f"\n  {yellow('Output is UNSIGNED. Re-sign before flashing.')}")

    print(f"\n  {green('Done!')} {dst_apk}")
    hr()
    return True


# ---
# TUI helpers
# ---
def ask_sign_mode():
    print()
    print(f"  {bold('Signing options:')}")
    print(f"  {bold('1')}  AOSP testkey     - use for devices signed with AOSP testkey")
    print(f"       {dim('(SHA-1: 27196e386b875e76adf700e7ea84e4c6eee33dfa)')}")
    print(f"  {bold('2')}  Custom key       - provide your own .pk8 + .x509.pem")
    print(f"  {bold('3')}  Skip signing     - output unsigned APK (you sign manually)")
    print()
    choice = _input("  Choice [1/2/3]: ").strip()

    if choice == "1":
        if not os.path.exists(TESTKEY_PK8):
            print(f"  {red('ERROR:')} AOSP testkey not found at {TESTKEY_PK8}")
            return None, None, None
        return "testkey", None, None

    elif choice == "2":
        pk8  = _input("\n  Path to .pk8 private key:\n  > ").strip().strip("'\"")
        cert = _input("  Path to .x509.pem certificate:\n  > ").strip().strip("'\"")
        if not os.path.exists(pk8):
            print(f"  {red('ERROR:')} Key not found: {pk8}")
            return None, None, None
        if not os.path.exists(cert):
            print(f"  {red('ERROR:')} Certificate not found: {cert}")
            return None, None, None
        return "custom", pk8, cert

    elif choice == "3":
        return None, None, None

    else:
        print(f"  {red('Invalid choice.')}")
        return None, None, None


def tui():
    print()
    print(bold("╔" + "═" * 52 + "╗"))
    print(bold("║") + "           MMS Quality Patcher                      " + bold("║"))
    print(bold("║") + "  Fixes MMS on Android:                              " + bold("║"))
    print(bold("║") + "   • Full-resolution images                          " + bold("║"))
    print(bold("║") + "   • Voice notes playable                            " + bold("║"))
    print(bold("║") + "   • Other MMS media at full size                    " + bold("║"))
    print(bold("╚" + "═" * 52 + "╝"))
    print()
    print(f"  {bold('1')}  Check APK   - inspect current MMS strings")
    print(f"  {bold('2')}  Patch APK   - apply fix and optionally sign")
    print(f"  {bold('3')}  Quit")
    print()

    choice = _input("  Choice [1/2/3]: ").strip()
    print()

    if choice == "1":
        apk = _input("  APK path (drag & drop works):\n  > ").strip().strip("'\"")
        status = cmd_check(apk)

        needs_patch = status and (
            (status["ua_pool_index"] is not None   and not status["patched_ua"]) or
            (status["uaprof_pool_index"] is not None and not status["patched_uaprof"])
        )

        if needs_patch:
            print()
            go = _input(f"  {yellow('Needs patching.')} Patch it now? [y/N]: ").strip().lower()
            if go == "y":
                default_out = apk.replace(".apk", "_patched.apk")
                if default_out == apk:
                    default_out = apk + "_patched.apk"
                print(f"\n  Output path (Enter for default):")
                print(f"  {dim('[' + default_out + ']')}")
                out = _input("  > ").strip().strip("'\"") or default_out
                sign_mode, pk8, cert = ask_sign_mode()
                cmd_patch(apk, out, pk8=pk8, cert=cert, sign_mode=sign_mode)
        elif status and status["patched_ua"] and status["patched_uaprof"]:
            print(f"\n  {green('This APK is already fully patched.')}")

    elif choice == "2":
        src = _input("  Source APK (drag & drop works):\n  > ").strip().strip("'\"")
        default_out = src.replace(".apk", "_patched.apk")
        if default_out == src:
            default_out = src + "_patched.apk"
        out = _input(
            f"\n  Output path (Enter for default):\n"
            f"  {dim('[' + default_out + ']')}\n  > "
        ).strip().strip("'\"") or default_out
        sign_mode, pk8, cert = ask_sign_mode()
        cmd_patch(src, out, pk8=pk8, cert=cert, sign_mode=sign_mode)

    elif choice == "3":
        print("  Bye.")
        sys.exit(0)

    else:
        print(f"  {red('Invalid choice.')} Enter 1, 2, or 3.")

    print()
    if _input("  Run again? [y/N]: ").strip().lower() == "y":
        print()
        tui()


# ---
# Entry point
# ---
if __name__ == "__main__":
    if len(sys.argv) == 1:
        tui()
    elif sys.argv[1] == "check" and len(sys.argv) == 3:
        cmd_check(sys.argv[2])
    elif sys.argv[1] == "patch" and len(sys.argv) == 4:
        cmd_patch(sys.argv[2], sys.argv[3])
    else:
        print(__doc__)
        sys.exit(1)
