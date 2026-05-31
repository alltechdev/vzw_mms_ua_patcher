"""
Synthetic APK factory for testing patch_rro.py.
Builds minimal but structurally valid resources.arsc files with MMS strings.
No external APK files needed.
"""
import struct
import zipfile
import io


# ---------------------------------------------------------------------------
# String pool builder
# ---------------------------------------------------------------------------
def _varint(val):
    if val >= 0x80:
        return bytes([(val >> 8) | 0x80, val & 0xFF])
    return bytes([val])


def build_utf8_pool(strings):
    """Build a UTF-8 ResStringPool chunk for the given list of strings."""
    string_count  = len(strings)
    HEADER_FIXED  = 28  # type(2)+headerSize(2)+chunkSize(4)+stringCount(4)+styleCount(4)+flags(4)+stringsStart(4)+stylesStart(4)

    # Encode each string into pool data format
    offsets = []
    data    = bytearray()
    for s in strings:
        offsets.append(len(data))
        sb = s.encode("utf-8")
        data += _varint(len(s))       # char count
        data += _varint(len(sb))      # byte count
        data += sb
        data += b"\x00"               # null terminator

    # 4-byte align data
    while len(data) % 4:
        data += b"\x00"

    offset_table  = struct.pack(f"<{string_count}I", *offsets)
    strings_start = HEADER_FIXED + len(offset_table)
    chunk_size    = strings_start + len(data)

    # Pad chunk to 4-byte alignment
    while chunk_size % 4:
        data += b"\x00"
        chunk_size = strings_start + len(data)

    header  = struct.pack("<HHI", 0x0001, HEADER_FIXED, chunk_size)
    header += struct.pack("<IIIII",
        string_count, 0,      # stringCount, styleCount
        0x100,                # flags: UTF8_FLAG
        strings_start,        # stringsStart
        0,                    # stylesStart
    )
    return bytes(header + offset_table + data)


# ---------------------------------------------------------------------------
# ResTable builder
# ---------------------------------------------------------------------------
def build_arsc(ua_value, uaprof_value, extra_strings=None):
    """
    Build a minimal resources.arsc containing:
      config_mms_user_agent        → ua_value
      config_mms_user_agent_profile_url → uaprof_value
    extra_strings: additional strings to add to global pool (optional).
    """
    extra_strings = extra_strings or []

    # Global string pool: index 0 = empty, 1 = ua_value, 2 = uaprof_value
    global_strings = ["", ua_value, uaprof_value] + extra_strings
    global_pool    = build_utf8_pool(global_strings)

    # Type string pool: ["string"]
    type_pool = build_utf8_pool(["string"])

    # Key string pool: two resource keys
    key_pool  = build_utf8_pool([
        "config_mms_user_agent",
        "config_mms_user_agent_profile_url",
    ])

    # ResTable_typeSpec  (type=0x0202): 2 entries, no flags
    typespec_data   = struct.pack("<II", 0, 0)
    typespec_chunk  = struct.pack("<HHI", 0x0202, 8, 8 + 4 + len(typespec_data))
    typespec_chunk += struct.pack("<I", 2)   # entryCount
    typespec_chunk += typespec_data

    # ResTable_type  (type=0x0201)
    #   header: type(2)+headerSize(2)+chunkSize(4)+id(1)+flags(1)+reserved(2)+entryCount(4)+entriesStart(4)+config(48)
    CONFIG         = bytes(48)   # all-zero = default config
    ENTRY_SIZE     = 8           # sizeof(ResTable_entry)
    VALUE_SIZE     = 8           # sizeof(ResTable_value)
    ENTRY_COUNT    = 2
    TYPE_HDR_SIZE  = 8 + 4 + 8 + len(CONFIG)   # = 68
    OFFSET_TABLE   = ENTRY_COUNT * 4            # = 8
    ENTRIES_START  = TYPE_HDR_SIZE + OFFSET_TABLE

    # Each row: ResTable_entry(8) + ResTable_value(8)
    def make_entry(key_idx, global_pool_idx):
        entry = struct.pack("<HHI", ENTRY_SIZE, 0, key_idx)          # simple entry
        value = struct.pack("<HBBI", VALUE_SIZE, 0, 0x03, global_pool_idx)  # TYPE_STRING
        return entry + value

    entry0     = make_entry(0, 1)   # config_mms_user_agent      → global[1] = ua_value
    entry1     = make_entry(1, 2)   # config_mms_user_agent_profile_url → global[2] = uaprof_value
    entry_data = entry0 + entry1
    chunk_size = ENTRIES_START + len(entry_data)

    type_header  = struct.pack("<HHI", 0x0201, TYPE_HDR_SIZE, chunk_size)
    type_header += struct.pack("<BBH", 1, 0, 0)          # id=1(string), flags=0, reserved
    type_header += struct.pack("<II", ENTRY_COUNT, ENTRIES_START)
    type_header += CONFIG
    offsets_raw  = struct.pack("<II", 0, ENTRY_SIZE + VALUE_SIZE)
    type_chunk   = type_header + offsets_raw + entry_data

    # ResTable_package  (type=0x0200)
    PKG_HDR_SIZE = 288
    name_utf16   = "android.auto_generated_rro_product__".encode("utf-16-le")
    name_field   = (name_utf16 + b"\x00" * 256)[:256]   # char16 name[128]

    type_strings_off = PKG_HDR_SIZE                        # right after header
    key_strings_off  = type_strings_off + len(type_pool)
    pkg_chunks       = typespec_chunk + type_chunk
    pkg_chunk_size   = PKG_HDR_SIZE + len(type_pool) + len(key_pool) + len(pkg_chunks)

    pkg_header  = struct.pack("<HHI", 0x0200, PKG_HDR_SIZE, pkg_chunk_size)
    pkg_header += struct.pack("<I", 0x7F)                  # package id
    pkg_header += name_field
    pkg_header += struct.pack("<IIIII",
        type_strings_off,
        1,                 # lastPublicType
        key_strings_off,
        2,                 # lastPublicKey
        0,                 # typeIdOffset
    )
    package = pkg_header + type_pool + key_pool + pkg_chunks

    # ResTable wrapper
    RT_HDR_SIZE = 12  # type(2)+headerSize(2)+chunkSize(4)+packageCount(4)
    total_size  = RT_HDR_SIZE + len(global_pool) + len(package)
    restable    = struct.pack("<HHI", 0x0002, RT_HDR_SIZE, total_size)
    restable   += struct.pack("<I", 1)   # packageCount
    return restable + global_pool + package


def build_apk(arsc_bytes, **extra_files):
    """
    Wrap resources.arsc in a minimal APK (ZIP).
    extra_files: filename -> bytes for additional entries.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as z:
        z.writestr("resources.arsc", arsc_bytes)
        for name, data in extra_files.items():
            z.writestr(name, data)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Convenience fixtures
# ---------------------------------------------------------------------------
TARGET_UA     = "odopcph2583"
TARGET_UAPROF = "http://uaprof.vtext.com/OnePlus/odopcph2583/odopcph2583.xml"


def stock_m5_apk():
    """Minimal APK with variant-A stock MMS values (Android-Mms/0.1 + kila URL)."""
    return build_apk(build_arsc(
        "Android-Mms/0.1",
        "http://www.google.com/oha/rdf/ua-profile-kila.xml",
    ))


def stock_f21_apk():
    """Minimal APK with variant-B stock values (Android-Mms/2.0 + Sony URL)."""
    return build_apk(build_arsc(
        "Android-Mms/2.0",
        "http://uaprof.sonymobile.com/H8296R5111.xml",
    ))


def patched_apk():
    """Minimal APK already patched to target values."""
    return build_apk(build_arsc(TARGET_UA, TARGET_UAPROF))


def no_mms_apk():
    """Minimal APK with no MMS-related strings at all."""
    return build_apk(build_arsc("some_other_value", "http://example.com/other.xml"))


def custom_ua_apk(ua, uaprof):
    """Minimal APK with arbitrary MMS values."""
    return build_apk(build_arsc(ua, uaprof))


def empty_zip():
    """Valid ZIP with no resources.arsc."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", b"<manifest/>")
    return buf.getvalue()
