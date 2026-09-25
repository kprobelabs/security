import faulthandler

from PIL import Image, ImageCms, features


def main():
    faulthandler.enable()

    print(f"Pillow={Image.__version__} littlecms2={features.check_module('littlecms2')}", flush=True)

    profile = ImageCms.createProfile("sRGB")
    transform = ImageCms.buildTransform(profile, profile, "RGB", "RGBA")
    source = Image.new("RGB", (64, 64), (1, 2, 3))

    print(f"before mutation: input_mode={transform.input_mode!r} output_mode={transform.output_mode!r}", flush=True)
    transform.output_mode = "L"
    print(f"after mutation: input_mode={transform.input_mode!r} output_mode={transform.output_mode!r}", flush=True)
    print("calling ImageCms.applyTransform", flush=True)

    ImageCms.applyTransform(source, transform)

    print("returned from ImageCms.applyTransform", flush=True)

    for _ in range(128):
        ImageCms.createProfile("sRGB").tobytes()

    print("completed allocator churn", flush=True)


if __name__ == "__main__":
    main()
