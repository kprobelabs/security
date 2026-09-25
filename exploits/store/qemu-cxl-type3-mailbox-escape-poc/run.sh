set -eu

QEMU="${1:-qemu-system-x86_64}"
IMAGE="${2:-poc.img}"
MARKER="/tmp/qemu_cxl_escape_marker"
SERIAL="run/serial.log"
STDOUT_LOG="run/qemu.stdout.log"
STDERR_LOG="run/qemu.stderr.log"

mkdir -p run
rm -f "$MARKER" "$SERIAL" "$STDOUT_LOG" "$STDERR_LOG"

timeout 60s "$QEMU" \
  -display none \
  -nodefaults \
  -machine q35,cxl=on,cxl-fmw.0.targets.0=cxl.0,cxl-fmw.0.size=4G \
  -device pxb-cxl,id=cxl.0,bus=pcie.0,bus_nr=52 \
  -device cxl-rp,id=rp0,bus=cxl.0,chassis=0,slot=0 \
  -object memory-backend-ram,id=cxl-mem0,size=256M \
  -object memory-backend-ram,id=cxl-dc0,size=256M \
  -device cxl-type3,bus=rp0,volatile-memdev=cxl-mem0,volatile-dc-memdev=cxl-dc0,num-dc-regions=1,id=mem0 \
  -drive file="$IMAGE",format=raw,if=floppy \
  -boot a \
  -serial file:"$SERIAL" \
  -no-reboot >"$STDOUT_LOG" 2>"$STDERR_LOG" || true

cat "$SERIAL"
test -f "$MARKER"
cat "$MARKER"
