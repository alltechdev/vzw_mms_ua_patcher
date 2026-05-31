# Signing

The patched APK must be re-signed before flashing.

Check what key the original uses:

```bash
apksigner verify --print-certs original.apk | grep SHA-1
```

- SHA-1 `27196e386b875e76adf700e7ea84e4c6eee33dfa` = AOSP testkey (bundled in `keys/`)
- Any other value = provide your own `.pk8` + `.x509.pem`
