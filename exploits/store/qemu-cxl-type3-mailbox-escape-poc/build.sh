set -eu

nasm -f bin boot.asm -o boot.bin
gcc -m32 -ffreestanding -nostdlib -fno-builtin -fno-pic -fno-pie -fno-stack-protector -Wall -Wextra -c stage2.c -o stage2.o
ld -m elf_i386 -T stage2.ld --oformat binary stage2.o -o stage2.bin
python3 - <<'PY'
from pathlib import Path
boot = Path("boot.bin").read_bytes()
stage = Path("stage2.bin").read_bytes()
image = boot + stage.ljust(16 * 512, b"\0")
Path("poc.img").write_bytes(image.ljust(1474560, b"\0"))
print(f"boot={len(boot)} stage={len(stage)} image=1474560")
PY
sha256sum poc.img boot.asm stage2.c stage2.ld
