# Verizon MMS Fix

Terminal UI tool that fixes Verizon MMS on Android:
- Images delivered at full resolution
- Voice notes received in the correct format and playable
- Other MMS media delivered at full size

Patches the MMS User-Agent and UAProf URL in the device's framework overlay APK.

## Requirements

- Python 3.8+
- Java (for signing) - `apksigner.jar` is included

## Usage

```bash
python3 patch_rro.py
```

## Tested Devices

| Device | Result |
|---|---|
| Qin F21 Pro (MT6761, Android 11) | Verified - MMS image size 5x increase confirmed on wire |
| Tiq M5 (MT6761, Android 11) | Verified |

Works on any Android device that uses this overlay mechanism for MMS config.

## What to patch

The APK is located on the device at:

```
/product/overlay/framework-res__auto_generated_rro_product.apk
```

## Files

```
patch_rro.py        - run this
keys/               - AOSP testkey
bin/apksigner.jar   - signing tool (requires Java)
docs/               - details
tests/              - test suite
```
