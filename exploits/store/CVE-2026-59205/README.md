# Pillow ImageCmsTransform Mutable `output_mode` OOB Write PoC

This entry documents and exercises a mode-validation bypass in Pillow `12.3.0`.

`ImageCms.buildTransform()` creates a reusable LittleCMS-backed transform and stores Python-side `input_mode` and `output_mode` attributes on the wrapper object. `ImageCmsTransform.apply()` checks those mutable Python attributes, allocates the destination image from `output_mode`, and then passes raw image capsules to the underlying C transform.

When a transform is built as `RGB` to `RGBA`, the C transform continues to operate with an RGBA-like output format. If `transform.output_mode` is changed to `L` before calling the normal high-level `ImageCms.applyTransform()` API, Pillow allocates a 1-byte-per-pixel output image while the C extension still copies auxiliary channel bytes using the original 4-byte-per-pixel transform layout. The result is a heap out-of-bounds write in `_imagingcms`.

## Affected Target

- Product: Pillow
- Version verified: `12.3.0`
- Release tag tested: `12.3.0`
- Feature path: `PIL.ImageCms`
- Build feature required: LittleCMS2 support enabled
- Public API path: `ImageCms.applyTransform(image, transform)`

## Impact

The PoC reaches a heap out-of-bounds write from ordinary Python API calls against a stock Pillow build with `_imagingcms` enabled. In a normal glibc run, the process aborts after heap metadata corruption is detected. In an AddressSanitizer run, the write is reported in `_imagingcms.c` during the auxiliary-channel copy.

## Source Trace

Relevant source locations in Pillow `12.3.0`:

| File | Behavior |
| --- | --- |
| `src/PIL/ImageCms.py` | Builds the C transform and stores mutable `input_mode` / `output_mode` attributes |
| `src/PIL/ImageCms.py` | `ImageCmsTransform.apply()` compares image modes against the mutable Python attributes |
| `src/PIL/ImageCms.py` | `ImageCmsTransform.apply()` allocates a new destination image in `self.output_mode` |
| `src/PIL/ImageCms.py` | `ImageCms.applyTransform()` reaches `transform.apply(im)` for the normal high-level path |
| `src/_imagingcms.c` | `cms_transform_apply()` checks only that arguments are valid Pillow image capsules |
| `src/_imagingcms.c` | `pyCMSdoTransform()` calls `cmsDoTransform()` and then `pyCMScopyAux()` |
| `src/_imagingcms.c` | `pyCMScopyAux()` derives destination stride and channel offsets from the LittleCMS transform format |

The high-level chain is:

```text
ImageCms.applyTransform(source, transform)
  transform.apply(source)
    Image.new(transform.output_mode, source.size, None)
    transform.transform.apply(source.getim(), output.getim())
      cms_transform_apply()
        pyCMSdoTransform()
          cmsDoTransform()
          pyCMScopyAux()
            memcpy(pDstExtras + x * dstChunkSize, ...)
```

The wrapper state and C transform state diverge:

```text
Original transform: RGB -> RGBA
Python output_mode after mutation: L
Allocated output image: 64 * 64 * 1 = 4096 bytes
C auxiliary copy layout: 4 bytes per pixel
Observed write: 3 bytes after the 4096-byte output allocation
```

The relevant Python wrapper code stores mutable mode metadata:

```text
src/PIL/ImageCms.py:310
self.input_mode = self.inputMode = input_mode
src/PIL/ImageCms.py:312
self.output_mode = self.outputMode = output_mode
```

The same wrapper trusts that metadata for validation and allocation:

```text
src/PIL/ImageCms.py:320
if im.mode != self.input_mode:
src/PIL/ImageCms.py:324
if imOut.mode != self.output_mode:
src/PIL/ImageCms.py:328
imOut = Image.new(self.output_mode, im.size, None)
src/PIL/ImageCms.py:329
self.transform.apply(im.getim(), imOut.getim())
```

The high-level API reaches the wrapper directly:

```text
src/PIL/ImageCms.py:738
imOut = transform.apply(im)
```

The C entry point validates capsule type and then applies the transform:

```text
src/_imagingcms.c:540
if (!PyCapsule_IsValid(i0, IMAGING_MAGIC) ||
src/_imagingcms.c:550
imOut = (Imaging)PyCapsule_GetPointer(i1, IMAGING_MAGIC);
src/_imagingcms.c:555
return Py_BuildValue("i", pyCMSdoTransform(im, imOut, self->transform));
```

The auxiliary copy uses transform-derived chunk sizes:

```text
src/_imagingcms.c:315
srcChunkSize = (T_CHANNELS(srcLCMSFormat) + T_EXTRA(srcLCMSFormat)) * channelSize;
src/_imagingcms.c:316
dstChunkSize = (T_CHANNELS(dstLCMSFormat) + T_EXTRA(dstLCMSFormat)) * channelSize;
src/_imagingcms.c:329
memcpy(pDstExtras + x * dstChunkSize, ...);
```

## PoC Design

`poc.py`:

1. Creates an sRGB profile.
2. Builds an `RGB` to `RGBA` ImageCms transform.
3. Creates a 64 x 64 RGB source image.
4. Changes `transform.output_mode` to `L`.
5. Calls `ImageCms.applyTransform(source, transform)`.
6. Performs allocator activity after the call if the process returns.

The script uses Pillow's Python API only.

## Requirements

- Python 3.10 or newer
- Pillow `12.3.0`
- LittleCMS2 support enabled in Pillow

Confirm LittleCMS2 support:

```bash
python -c "from PIL import features; print(features.check_module('littlecms2'))"
```

The command should print `True`.

## Quick Run

Install or select a stock Pillow `12.3.0` build with LittleCMS2 enabled, then run:

```bash
python poc.py
```

Expected stock-output shape:

```text
Pillow=12.3.0 littlecms2=True
before mutation: input_mode='RGB' output_mode='RGBA'
after mutation: input_mode='RGB' output_mode='L'
calling ImageCms.applyTransform
malloc(): invalid size (unsorted)
Fatal Python error: Aborted
```

Allocator diagnostics vary by platform and build. The important condition is that the crash occurs after the normal `ImageCms.applyTransform()` call with a stock Pillow `_imagingcms` extension.

## AddressSanitizer Confirmation

With the same Pillow `12.3.0` source built under AddressSanitizer, the PoC reports:

```text
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 1
    #1 ... in pyCMScopyAux _imagingcms.c
    #2 ... in pyCMSdoTransform _imagingcms.c
    #3 ... in cms_transform_apply _imagingcms.c
0x... is located 3 bytes after 4096-byte region
SUMMARY: AddressSanitizer: heap-buffer-overflow _imagingcms.c in pyCMScopyAux
```

The 4096-byte region is the `L` output image allocated by the high-level wrapper after `output_mode` is changed.

## Validation Run

The validation run used a clean official Pillow `12.3.0` source checkout built with LittleCMS2 enabled.

Stock run:

```text
Pillow=12.3.0 littlecms2=True
before mutation: input_mode='RGB' output_mode='RGBA'
after mutation: input_mode='RGB' output_mode='L'
calling ImageCms.applyTransform
malloc(): invalid size (unsorted)
Fatal Python error: Aborted
  File ".../PIL/ImageCms.py", line 273 in tobytes
  File ".../PIL/ImageCms.py", line 330 in apply
  File ".../PIL/ImageCms.py", line 738 in applyTransform
  File ".../poc.py", line 20 in main
```

Sanitizer run:

```text
ERROR: AddressSanitizer: heap-buffer-overflow on address ...
WRITE of size 1
    #1 ... in pyCMScopyAux _imagingcms.c
    #2 ... in pyCMSdoTransform _imagingcms.c
    #3 ... in cms_transform_apply _imagingcms.c
0x... is located 3 bytes after 4096-byte region
```

## Fix Direction

- Keep immutable expected input and output mode information on the C transform object.
- Validate the actual source and destination `Imaging` mode or pixel size in `_imagingcms.c` before calling `pyCMSdoTransform()`.
- Compare the source image against `cmsGetTransformInputFormat(self->transform)`.
- Compare the destination image against `cmsGetTransformOutputFormat(self->transform)`.
- Reject a destination image whose pixel size is smaller than the transform output format requires.
- Avoid relying on mutable Python wrapper attributes for native memory-safety checks.

## Responsible Use

Use this PoC only for systems you own, systems you are authorized to test, and defensive regression work.
