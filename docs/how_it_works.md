# How It Works

When an Android device downloads an MMS, it sends two HTTP headers to the carrier MMSC:

- **User-Agent** - device identifier
- **Profile** - URL to a UAProf XML that declares the device's capabilities

The carrier reads the UAProf and may transcode media to fit within the declared limits.
Devices that ship with incorrect UAProf values receive degraded media.

These values are stored in `resources.arsc` inside:

```
/product/overlay/framework-res__auto_generated_rro_product.apk
```

The patcher edits those two strings directly in the binary, no recompilation.
Everything else in the APK is unchanged.
