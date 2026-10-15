// One MPC party implemented with upstream's public C API (include/cbmpc/c_api),
// talking to JS parties through stdin/stdout. Used by run.ts to check that
// cb-mpc-ts interoperates with the original C library.
//
// Frames (little-endian int32 header):
//   stdin  : [from][len][bytes]   message from party `from`
//   stdout : [to][len][bytes]     message to party `to`
//            [-1][len][bytes]     result: public key (compressed), then signature
//
// Usage: party <ecdsa2p|eddsa2p|ecdsamp|eddsamp|ecdsaac|eddsaac> <self> <n> <curve> <msg-hex>
//
// ecdsaac / eddsaac (n = 3, parties iphone, mac, server): dkg_ac 2-of-3, then mac + server reshare a new
// generation for all three (lost-device flow), then all three sign_ac. Result frames: public key, signature.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cbmpc/c_api/access_structure.h>
#include <cbmpc/c_api/common.h>
#include <cbmpc/c_api/ecdsa_2p.h>
#include <cbmpc/c_api/ecdsa_mp.h>
#include <cbmpc/c_api/eddsa_2p.h>
#include <cbmpc/c_api/eddsa_mp.h>
#include <cbmpc/c_api/job.h>

#define MAX_PARTIES 8

typedef struct msg_node {
  uint8_t* data;
  int size;
  struct msg_node* next;
} msg_node;

static msg_node* inbox[MAX_PARTIES];  // per-sender FIFO of frames read ahead

static void die(const char* what, int rv) {
  fprintf(stderr, "c-party: %s failed: 0x%08x\n", what, (unsigned)rv);
  exit(1);
}

static int read_full(void* buf, size_t n) { return fread(buf, 1, n, stdin) == n ? 0 : -1; }

static void write_frame(int32_t to, const uint8_t* data, int size) {
  int32_t hdr[2] = {to, size};
  fwrite(hdr, sizeof(hdr), 1, stdout);
  if (size) fwrite(data, 1, (size_t)size, stdout);
  fflush(stdout);
}

static cbmpc_error_t t_send(void* ctx, int32_t receiver, const uint8_t* data, int size) {
  (void)ctx;
  write_frame(receiver, data, size);
  return CBMPC_SUCCESS;
}

static cbmpc_error_t t_receive(void* ctx, int32_t sender, cmem_t* out) {
  (void)ctx;
  if (sender < 0 || sender >= MAX_PARTIES) return CBMPC_E_BADARG;
  while (!inbox[sender]) {
    int32_t hdr[2];
    if (read_full(hdr, sizeof(hdr))) return CBMPC_E_NET_GENERAL;
    if (hdr[0] < 0 || hdr[0] >= MAX_PARTIES || hdr[1] < 0) return CBMPC_E_NET_GENERAL;
    msg_node* m = calloc(1, sizeof(msg_node));
    m->size = hdr[1];
    m->data = cbmpc_malloc(m->size ? (size_t)m->size : 1);
    if (m->size && read_full(m->data, (size_t)m->size)) return CBMPC_E_NET_GENERAL;
    msg_node** tail = &inbox[hdr[0]];
    while (*tail) tail = &(*tail)->next;
    *tail = m;
  }
  msg_node* m = inbox[sender];
  inbox[sender] = m->next;
  out->data = m->data;  // freed by the library with cbmpc_free
  out->size = m->size;
  free(m);
  return CBMPC_SUCCESS;
}

static cbmpc_error_t t_receive_all(void* ctx, const int32_t* senders, int count, cmems_t* out) {
  cmem_t* parts = calloc((size_t)count, sizeof(cmem_t));
  int total = 0;
  for (int i = 0; i < count; i++) {
    cbmpc_error_t rv = t_receive(ctx, senders[i], &parts[i]);
    if (rv) return rv;
    total += parts[i].size;
  }
  out->count = count;
  out->sizes = cbmpc_malloc(sizeof(int) * (size_t)count);
  out->data = cbmpc_malloc(total ? (size_t)total : 1);
  int off = 0;
  for (int i = 0; i < count; i++) {
    out->sizes[i] = parts[i].size;
    if (parts[i].size) memcpy(out->data + off, parts[i].data, (size_t)parts[i].size);
    off += parts[i].size;
    cbmpc_free(parts[i].data);
  }
  free(parts);
  return CBMPC_SUCCESS;
}

static cmem_t from_hex(const char* hex) {
  size_t n = strlen(hex) / 2;
  cmem_t m = {malloc(n ? n : 1), (int)n};
  for (size_t i = 0; i < n; i++) sscanf(hex + 2 * i, "%2hhx", &m.data[i]);
  return m;
}

// THRESHOLD[2](iphone, mac, server); dkg_ac, reshare (dealers mac + server), sign_ac with all three.
static void run_ac(int eddsa, int self, cbmpc_curve_id_t curve, cmem_t msg, cmem_t* pub, cmem_t* sig) {
  static const char* names[3] = {"iphone", "mac", "server"};
  static const char* dealers[2] = {"mac", "server"};
  static const int32_t child_indices[] = {1, 2, 3};
  static const cbmpc_access_structure_node_t nodes[] = {
      {CBMPC_ACCESS_STRUCTURE_NODE_THRESHOLD, NULL, 2, 0, 3},
      {CBMPC_ACCESS_STRUCTURE_NODE_LEAF, "iphone", 0, 0, 0},
      {CBMPC_ACCESS_STRUCTURE_NODE_LEAF, "mac", 0, 0, 0},
      {CBMPC_ACCESS_STRUCTURE_NODE_LEAF, "server", 0, 0, 0},
  };
  const cbmpc_access_structure_t ac = {nodes, 4, child_indices, 3, 0};
  cbmpc_transport_t transport = {NULL, t_send, t_receive, t_receive_all, NULL};
  cbmpc_mp_job_t job = {self, names, 3, &transport};
  cmem_t none = {NULL, 0}, g0 = {0}, g1 = {0}, sid = {0}, x = {0};
  cbmpc_error_t rv;

  rv = eddsa ? cbmpc_eddsa_mp_dkg_ac(&job, curve, none, &ac, names, 3, &g0, &sid)
             : cbmpc_ecdsa_mp_dkg_ac(&job, curve, none, &ac, names, 3, &g0, &sid);
  if (rv) die("dkg_ac", rv);
  rv = eddsa ? cbmpc_eddsa_mp_get_public_key_compressed(g0, pub) : cbmpc_ecdsa_mp_get_public_key_compressed(g0, pub);
  if (rv) die("get_public_key", rv);
  if (self != 0) {
    rv = eddsa ? cbmpc_eddsa_mp_ac_key_to_additive_share(g0, &ac, dealers, 2, &x)
               : cbmpc_ecdsa_mp_ac_key_to_additive_share(g0, &ac, dealers, 2, &x);
    if (rv) die("ac_key_to_additive_share", rv);
  }
  rv = eddsa ? cbmpc_eddsa_mp_reshare_from_additive(&job, curve, none, *pub, dealers, 2, x, &ac, NULL, &g1)
             : cbmpc_ecdsa_mp_reshare_from_additive(&job, curve, none, *pub, dealers, 2, x, &ac, NULL, &g1);
  if (rv) die("reshare_from_additive", rv);
  rv = eddsa ? cbmpc_eddsa_mp_sign_ac(&job, g1, &ac, msg, 0, sig) : cbmpc_ecdsa_mp_sign_ac(&job, g1, &ac, msg, 0, sig);
  if (rv) die("sign_ac", rv);
  cbmpc_cmem_free(x);
  cbmpc_cmem_free(g0);
  cbmpc_cmem_free(g1);
  cbmpc_cmem_free(sid);
}

int main(int argc, char** argv) {
  if (argc != 6) {
    fprintf(stderr, "usage: party <ecdsa2p|eddsa2p|ecdsamp|eddsamp|ecdsaac|eddsaac> <self> <n> <curve> <msg-hex>\n");
    return 2;
  }
  const char* proto = argv[1];
  int self = atoi(argv[2]), n = atoi(argv[3]);
  cbmpc_curve_id_t curve = (cbmpc_curve_id_t)atoi(argv[4]);
  cmem_t msg = from_hex(argv[5]);

  static char names_buf[MAX_PARTIES][8];
  const char* names[MAX_PARTIES];
  for (int i = 0; i < n; i++) {
    snprintf(names_buf[i], sizeof(names_buf[i]), "p%d", i);
    names[i] = names_buf[i];
  }

  cbmpc_transport_t transport = {NULL, t_send, t_receive, t_receive_all, NULL};
  cbmpc_2pc_job_t job2 = {(cbmpc_2pc_party_t)self, names[0], names[1], &transport};
  cbmpc_mp_job_t jobm = {self, names, n, &transport};

  cmem_t key = {0}, pub = {0}, sig = {0}, sid = {0};
  cmem_t no_sid = {NULL, 0};
  cbmpc_error_t rv;

  if (!strcmp(proto, "ecdsa2p")) {
    if ((rv = cbmpc_ecdsa_2p_dkg(&job2, curve, &key))) die("ecdsa_2p_dkg", rv);
    if ((rv = cbmpc_ecdsa_2p_get_public_key_compressed(key, &pub))) die("get_public_key", rv);
    if ((rv = cbmpc_ecdsa_2p_sign(&job2, key, msg, no_sid, &sid, &sig))) die("ecdsa_2p_sign", rv);
  } else if (!strcmp(proto, "eddsa2p")) {
    if ((rv = cbmpc_eddsa_2p_dkg(&job2, curve, &key))) die("eddsa_2p_dkg", rv);
    if ((rv = cbmpc_eddsa_2p_get_public_key_compressed(key, &pub))) die("get_public_key", rv);
    if ((rv = cbmpc_eddsa_2p_sign(&job2, key, msg, &sig))) die("eddsa_2p_sign", rv);
  } else if (!strcmp(proto, "ecdsamp")) {
    if ((rv = cbmpc_ecdsa_mp_dkg_additive(&jobm, curve, &key, &sid))) die("ecdsa_mp_dkg", rv);
    if ((rv = cbmpc_ecdsa_mp_get_public_key_compressed(key, &pub))) die("get_public_key", rv);
    if ((rv = cbmpc_ecdsa_mp_sign_additive(&jobm, key, msg, 0, &sig))) die("ecdsa_mp_sign", rv);
  } else if (!strcmp(proto, "eddsamp")) {
    if ((rv = cbmpc_eddsa_mp_dkg_additive(&jobm, curve, &key, &sid))) die("eddsa_mp_dkg", rv);
    if ((rv = cbmpc_eddsa_mp_get_public_key_compressed(key, &pub))) die("get_public_key", rv);
    if ((rv = cbmpc_eddsa_mp_sign_additive(&jobm, key, msg, 0, &sig))) die("eddsa_mp_sign", rv);
  } else if (!strcmp(proto, "ecdsaac") || !strcmp(proto, "eddsaac")) {
    run_ac(proto[0] == 'e' && proto[1] == 'd', self, curve, msg, &pub, &sig);
  } else {
    fprintf(stderr, "unknown protocol %s\n", proto);
    return 2;
  }

  write_frame(-1, pub.data, pub.size);
  write_frame(-1, sig.data, sig.size);
  return 0;
}
