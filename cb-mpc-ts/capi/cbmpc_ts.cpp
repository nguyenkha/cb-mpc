#include "cbmpc_ts.h"

#include <climits>
#include <cstring>
#include <iostream>
#include <memory>
#include <set>
#include <string_view>
#include <vector>

#include <cbmpc/api/ecdsa_mp.h>
#include <cbmpc/api/eddsa_mp.h>
#include <cbmpc/api/pve_base_pke.h>
#include <cbmpc/api/pve_batch_single_recipient.h>
#include <cbmpc/core/buf.h>
#include <cbmpc/internal/core/log.h>
#include <cbmpc/internal/crypto/base.h>
#include <cbmpc/internal/protocol/agree_random.h>
#include <cbmpc/internal/protocol/ec_dkg.h>
#include <cbmpc/internal/protocol/ecdsa_2p.h>
#include <cbmpc/internal/protocol/ecdsa_mp.h>
#include <cbmpc/internal/protocol/eddsa.h>
#include <cbmpc/internal/protocol/mpc_job.h>
#include <cbmpc/internal/protocol/schnorr_2p.h>
#include <cbmpc/internal/zk/zk_ec.h>

#include "access_structure_codec.h"

using namespace coinbase;
using namespace coinbase::crypto;
using namespace coinbase::mpc;

// ===========================================================================
// cmem helpers
// ===========================================================================

namespace {

// Error from the last value-returning call on this thread (0 = none). Functions
// that return a cmem_t / handle by value have no status code of their own; the
// wasm_* wrappers read this to report failures to JS.
thread_local int g_last_error = 0;

template <typename R>
R fail(int err, R value) {
  g_last_error = err;
  return value;
}

mem_t view(cmem_t cmem) { return mem_t(cmem.data, cmem.size); }

cmem_t copy_to_cmem(mem_t mem) {
  cmem_t out{nullptr, mem.size};
  if (mem.size > 0) {
    out.data = static_cast<uint8_t*>(std::malloc(mem.size));
    if (!out.data) return fail(E_INSUFFICIENT, cmem_t{nullptr, 0});
    std::memmove(out.data, mem.data, mem.size);
  }
  return out;
}

// Total byte length of a cmems, or -1 when a size is negative, the total overflows, or data is missing.
int cmems_total_size(const cmems_t& cmems) {
  if (cmems.count < 0 || (cmems.count > 0 && !cmems.sizes)) return -1;
  int total = 0;
  for (int i = 0; i < cmems.count; i++) {
    const int sz = cmems.sizes[i];
    if (sz < 0 || sz > INT_MAX - total) return -1;
    total += sz;
  }
  if (total > 0 && !cmems.data) return -1;
  return total;
}

// Malformed cmems (see cmems_total_size) yield an empty vector, as if no items were given.
std::vector<buf_t> bufs_from_cmems(cmems_t cmems) {
  std::vector<buf_t> out;
  if (cmems.count <= 0 || cmems_total_size(cmems) < 0) return out;
  out.reserve(cmems.count);
  int offset = 0;
  for (int i = 0; i < cmems.count; i++) {
    const int sz = cmems.sizes[i];
    out.emplace_back(mem_t(cmems.data + offset, sz));
    offset += sz;
  }
  return out;
}

// Protocol messages can carry secret sub-shares (e.g. reshare / DKG `xij`): wipe before handing memory back.
void wipe_and_free(uint8_t* data, int size) {
  if (data && size > 0) coinbase::secure_bzero(data, size);
  std::free(data);
}

cmems_t copy_to_cmems(const std::vector<mem_t>& mems) {
  cmems_t out{0, nullptr, nullptr};
  const int count = static_cast<int>(mems.size());
  if (count == 0) return out;

  int total = 0;
  for (const auto& m : mems) total += m.size;

  out.data = static_cast<uint8_t*>(std::malloc(total > 0 ? total : 1));
  out.sizes = static_cast<int*>(std::malloc(sizeof(int) * count));
  if (!out.data || !out.sizes) {
    std::free(out.data);
    std::free(out.sizes);
    return cmems_t{0, nullptr, nullptr};
  }
  out.count = count;

  int offset = 0;
  for (int i = 0; i < count; i++) {
    out.sizes[i] = mems[i].size;
    if (mems[i].size) {
      std::memmove(out.data + offset, mems[i].data, mems[i].size);
      offset += mems[i].size;
    }
  }
  return out;
}

// C++ exceptions (cb_assert, std::bad_alloc, ...) must not cross the extern "C"
// boundary: on native FFI they would terminate the host process.
template <typename R, typename F>
R guard(R on_error, F&& f) noexcept {
  try {
    return f();
  } catch (const std::bad_alloc&) {
    g_last_error = E_INSUFFICIENT;
    return on_error;
  } catch (const std::exception& e) {
    std::cerr << "cb-mpc-ts: " << e.what() << std::endl;
  } catch (...) {
    std::cerr << "cb-mpc-ts: unknown exception" << std::endl;
  }
  g_last_error = E_GENERAL;
  return on_error;
}

template <typename F>
int guard_rv(F&& f) noexcept {
  return guard<int>(E_GENERAL, std::forward<F>(f));
}

// Returns E_INSUFFICIENT when the output buffers cannot be allocated.
int copy_to_cmems_rv(const std::vector<mem_t>& mems, cmems_t* out) {
  *out = copy_to_cmems(mems);
  return (!mems.empty() && out->count == 0) ? E_INSUFFICIENT : 0;
}

int copy_to_cmem_rv(mem_t mem, cmem_t* out) {
  *out = copy_to_cmem(mem);
  return (mem.size > 0 && !out->data) ? E_INSUFFICIENT : 0;
}

template <typename T>
T* as(void* opaque) {
  return static_cast<T*>(opaque);
}

// ===========================================================================
// Transport adapter: C callbacks -> coinbase::api::data_transport_i
// ===========================================================================

class callback_transport_t : public coinbase::api::data_transport_i {
 public:
  callback_transport_t(const data_transport_callbacks_t& callbacks, void* ctx) : callbacks_(callbacks), ctx_(ctx) {}

  error_t send(coinbase::api::party_idx_t receiver, mem_t msg) override {
    return error_t(callbacks_.send_fun(ctx_, receiver, cmem_t{const_cast<uint8_t*>(msg.data), msg.size}));
  }

  error_t receive(coinbase::api::party_idx_t sender, buf_t& msg) override {
    cmem_t cmsg{nullptr, 0};
    int rv = callbacks_.receive_fun(ctx_, sender, &cmsg);
    if (rv) {
      wipe_and_free(cmsg.data, cmsg.size);
      return error_t(rv);
    }
    if (cmsg.size < 0 || (cmsg.size > 0 && !cmsg.data)) {
      wipe_and_free(cmsg.data, 0);
      return NETWORK_ERROR;
    }
    msg = buf_t(view(cmsg));
    wipe_and_free(cmsg.data, cmsg.size);
    return SUCCESS;
  }

  error_t receive_all(const std::vector<coinbase::api::party_idx_t>& senders, std::vector<buf_t>& msgs) override {
    const int n = static_cast<int>(senders.size());
    msgs.clear();
    if (n == 0) return SUCCESS;

    std::vector<int> c_senders(senders.begin(), senders.end());
    cmems_t cmsgs{0, nullptr, nullptr};
    int rv = callbacks_.receive_all_fun(ctx_, c_senders.data(), n, &cmsgs);
    if (!rv && cmsgs.count != n) rv = NETWORK_ERROR;
    // Sizes are only trusted from a successful callback with the expected count.
    const int total = rv ? -1 : cmems_total_size(cmsgs);
    if (!rv && total < 0) rv = NETWORK_ERROR;
    if (!rv) msgs = bufs_from_cmems(cmsgs);
    wipe_and_free(cmsgs.data, total);
    std::free(cmsgs.sizes);
    return error_t(rv);
  }

 private:
  const data_transport_callbacks_t callbacks_;
  void* const ctx_;
};

// Internal MP job that also hands out its transport, so the access-structure calls can build a public-API job.
class ts_job_mp_t final : public job_mp_t {
 public:
  using job_mp_t::job_mp_t;
  coinbase::api::data_transport_i* api_transport() const { return transport_raw; }
};

bool valid_callbacks(const data_transport_callbacks_t* cb) {
  return cb && cb->send_fun && cb->receive_fun && cb->receive_all_fun;
}

bool valid_party_names(const char* const* pnames, int count) {
  if (!pnames) return false;
  for (int i = 0; i < count; ++i) {
    if (!pnames[i] || std::string_view(pnames[i]).empty()) return false;
  }
  return true;
}

job_2p_t* job_of(job_2p_ref* j) { return j && j->opaque ? as<job_2p_t>(j->opaque) : nullptr; }
job_mp_t* job_of(job_mp_ref* j) { return j && j->opaque ? as<job_mp_t>(j->opaque) : nullptr; }

template <typename REF>
bool valid_ref(const REF* r) {
  return r && r->opaque;
}

int x_share_bin_size(const bn_t& x, const ecurve_t& curve) {
  return std::max(x.get_bin_size(), curve.order().get_bin_size());
}


// ---------------------------------------------------------------------------
// Key validation at the deserialization boundary (mirrors upstream's
// api/*::blob_to_key checks). A valid key produced by any cb-mpc-ts version
// passes; a tampered or corrupted blob is rejected up front instead of
// failing later inside a protocol.
// ---------------------------------------------------------------------------

error_t check_point(const ecurve_t& curve, const ecc_point_t& P) {
  if (!curve.valid() || P.get_curve() != curve) return E_FORMAT;
  return curve.check(P) ? E_FORMAT : SUCCESS;
}

error_t validate_ecdsa2p_key(const ecdsa2pc::key_t& key) {
  if (!key.curve.valid() || key.curve == coinbase::crypto::curve_ed25519) return E_FORMAT;
  if (check_point(key.curve, key.Q)) return E_FORMAT;

  // P1 (role 0) holds the Paillier private key; c_key encrypts P1's share.
  const bool has_private = key.paillier.has_private_key();
  if ((key.role == party_t::p1) != has_private) return E_FORMAT;
  const mod_t& N = key.paillier.get_N();
  if (N.value().get_bits_count() < coinbase::crypto::paillier_t::bit_size) return E_FORMAT;
  // x_share may be unreduced mod q after refresh, but must stay in Z_N.
  if (!N.is_in_range(key.x_share)) return E_FORMAT;
  {
    coinbase::crypto::vartime_scope_t vartime_scope;
    if (key.paillier.verify_cipher(key.c_key)) return E_FORMAT;
  }
  if (has_private && key.paillier.decrypt(key.c_key) != N.mod(key.x_share)) return E_FORMAT;
  return SUCCESS;
}

error_t validate_eckey_2p_key(const eckey::key_share_2p_t& key) {
  if (!key.curve.valid()) return E_FORMAT;
  if (!key.curve.order().is_in_range(key.x_share)) return E_FORMAT;
  return check_point(key.curve, key.Q);
}

error_t validate_eckey_mp_key(const eckey::key_share_mp_t& key) {
  if (!key.curve.valid() || key.party_name.empty()) return E_FORMAT;
  if (!key.curve.order().is_in_range(key.x_share)) return E_FORMAT;
  if (check_point(key.curve, key.Q)) return E_FORMAT;

  ecc_point_t Q_sum = key.curve.infinity();
  for (const auto& kv : key.Qis) {
    if (check_point(key.curve, kv.second)) return E_FORMAT;
    Q_sum += kv.second;
  }
  if (key.Q != Q_sum) return E_FORMAT;

  const auto self = key.Qis.find(key.party_name);
  if (self == key.Qis.end()) return E_FORMAT;
  if (key.x_share * key.curve.generator() != self->second) return E_FORMAT;
  return SUCCESS;
}

}  // namespace

int cbmpc_ts_take_last_error(void) {
  int err = g_last_error;
  g_last_error = 0;
  return err;
}

// ===========================================================================
// Jobs
// ===========================================================================

job_2p_ref* new_job_2p(const data_transport_callbacks_t* callbacks, void* ctx, int party_index,
                       const char* const* pnames, int pname_count) {
  if (pname_count != 2 || !valid_callbacks(callbacks) || !valid_party_names(pnames, pname_count)) return nullptr;
  if (party_index != 0 && party_index != 1) return nullptr;
  try {
    auto transport = std::make_shared<callback_transport_t>(*callbacks, ctx);
    auto job = std::make_unique<job_2p_t>(party_t(party_index), std::string(pnames[0]), std::string(pnames[1]),
                                          transport);
    return new job_2p_ref{job.release()};
  } catch (const std::exception& e) {
    std::cerr << "new_job_2p: " << e.what() << std::endl;
    return nullptr;
  }
}

void free_job_2p(job_2p_ref* ptr) {
  if (!ptr) return;
  delete as<job_2p_t>(ptr->opaque);
  delete ptr;
}

int is_peer1(const job_2p_ref* job) { return valid_ref(job) && as<job_2p_t>(job->opaque)->is_p1() ? 1 : 0; }
int is_peer2(const job_2p_ref* job) { return valid_ref(job) && as<job_2p_t>(job->opaque)->is_p2() ? 1 : 0; }

int get_role_index(const job_2p_ref* job) {
  if (!valid_ref(job)) return -1;
  return static_cast<int>(as<job_2p_t>(job->opaque)->get_party_idx());
}

job_mp_ref* new_job_mp(const data_transport_callbacks_t* callbacks, void* ctx, int party_count, int party_index,
                       const char* const* pnames, int pname_count) {
  if (party_count <= 0 || pname_count != party_count) return nullptr;
  if (party_index < 0 || party_index >= party_count) return nullptr;
  if (!valid_callbacks(callbacks) || !valid_party_names(pnames, pname_count)) return nullptr;
  try {
    auto transport = std::make_shared<callback_transport_t>(*callbacks, ctx);
    std::vector<pname_t> names(pnames, pnames + party_count);
    auto job = std::make_unique<ts_job_mp_t>(party_index, std::move(names), transport);
    return new job_mp_ref{static_cast<job_mp_t*>(job.release())};
  } catch (const std::exception& e) {
    std::cerr << "new_job_mp: " << e.what() << std::endl;
    return nullptr;
  }
}

void free_job_mp(job_mp_ref* ptr) {
  if (!ptr) return;
  delete static_cast<ts_job_mp_t*>(as<job_mp_t>(ptr->opaque));
  delete ptr;
}

int get_party_idx(const job_mp_ref* job) {
  if (!valid_ref(job)) return -1;
  return static_cast<int>(as<job_mp_t>(job->opaque)->get_party_idx());
}

int get_n_parties(const job_mp_ref* job) {
  if (!valid_ref(job)) return -1;
  return static_cast<int>(as<job_mp_t>(job->opaque)->get_n_parties());
}

mpc_party_set_ref new_party_set(void) {
  return guard<mpc_party_set_ref>(mpc_party_set_ref{nullptr}, [] { return mpc_party_set_ref{new party_set_t()}; });
}

void party_set_add(mpc_party_set_ref* set, int party_idx) {
  if (valid_ref(set)) as<party_set_t>(set->opaque)->add(party_idx);
}

void free_party_set(mpc_party_set_ref ctx) { delete as<party_set_t>(ctx.opaque); }

// ===========================================================================
// Curves, points and scalars
// ===========================================================================

ecurve_ref new_ecurve(int curve_code) {
  return guard<ecurve_ref>(ecurve_ref{nullptr}, [&]() -> ecurve_ref {
    ecurve_t curve = ecurve_t::find(curve_code);
    if (!curve) return fail(E_BADARG, ecurve_ref{nullptr});
    return ecurve_ref{new ecurve_t(curve)};
  });
}

void free_ecurve(ecurve_ref ref) { delete as<ecurve_t>(ref.opaque); }

ecc_point_ref ecurve_generator(ecurve_ref* curve) {
  return guard<ecc_point_ref>(ecc_point_ref{nullptr}, [&]() -> ecc_point_ref {
    if (!valid_ref(curve)) return fail(E_BADARG, ecc_point_ref{nullptr});
    return ecc_point_ref{new ecc_point_t(as<ecurve_t>(curve->opaque)->generator())};
  });
}

cmem_t ecurve_order(ecurve_ref* curve) {
  return guard<cmem_t>(cmem_t{nullptr, 0}, [&]() -> cmem_t {
    if (!valid_ref(curve)) return fail(E_BADARG, cmem_t{nullptr, 0});
    bn_t order = as<ecurve_t>(curve->opaque)->order();
    return copy_to_cmem(order.to_bin());
  });
}

int ecurve_get_curve_code(ecurve_ref* curve) {
  return guard_rv([&]() -> int {
    if (!valid_ref(curve)) return -1;
    return as<ecurve_t>(curve->opaque)->get_openssl_code();
  });
}

cmem_t ecurve_random_scalar(ecurve_ref* curve) {
  return guard<cmem_t>(cmem_t{nullptr, 0}, [&]() -> cmem_t {
    if (!valid_ref(curve)) return fail(E_BADARG, cmem_t{nullptr, 0});
    const ecurve_t& c = *as<ecurve_t>(curve->opaque);
    bn_t k = c.get_random_value();
    return copy_to_cmem(k.to_bin(c.order().get_bin_size()));
  });
}

ecc_point_ref ecurve_mul_generator(ecurve_ref* curve, cmem_t scalar) {
  return guard<ecc_point_ref>(ecc_point_ref{nullptr}, [&]() -> ecc_point_ref {
    if (!valid_ref(curve)) return fail(E_BADARG, ecc_point_ref{nullptr});
    bn_t k = bn_t::from_bin(view(scalar));
    return ecc_point_ref{new ecc_point_t(as<ecurve_t>(curve->opaque)->mul_to_generator(k))};
  });
}

void free_ecc_point(ecc_point_ref ref) { delete as<ecc_point_t>(ref.opaque); }

ecc_point_ref ecc_point_from_bytes(cmem_t point_bytes) {
  return guard<ecc_point_ref>(ecc_point_ref{nullptr}, [&]() -> ecc_point_ref {
    auto point = std::make_unique<ecc_point_t>();
    if (coinbase::deser(view(point_bytes), *point)) return fail(E_BADARG, ecc_point_ref{nullptr});
    return ecc_point_ref{point.release()};
  });
}

cmem_t ecc_point_to_bytes(ecc_point_ref* point) {
  return guard<cmem_t>(cmem_t{nullptr, 0}, [&]() -> cmem_t {
    if (!valid_ref(point)) return fail(E_BADARG, cmem_t{nullptr, 0});
    return copy_to_cmem(coinbase::ser(*as<ecc_point_t>(point->opaque)));
  });
}

ecc_point_ref ecc_point_multiply(ecc_point_ref* point, cmem_t scalar) {
  return guard<ecc_point_ref>(ecc_point_ref{nullptr}, [&]() -> ecc_point_ref {
    if (!valid_ref(point)) return fail(E_BADARG, ecc_point_ref{nullptr});
    bn_t k = bn_t::from_bin(view(scalar));
    return ecc_point_ref{new ecc_point_t(k * (*as<ecc_point_t>(point->opaque)))};
  });
}

ecc_point_ref ecc_point_add(ecc_point_ref* point1, ecc_point_ref* point2) {
  return guard<ecc_point_ref>(ecc_point_ref{nullptr}, [&]() -> ecc_point_ref {
    if (!valid_ref(point1) || !valid_ref(point2)) return fail(E_BADARG, ecc_point_ref{nullptr});
    return ecc_point_ref{new ecc_point_t(*as<ecc_point_t>(point1->opaque) + *as<ecc_point_t>(point2->opaque))};
  });
}

ecc_point_ref ecc_point_subtract(ecc_point_ref* point1, ecc_point_ref* point2) {
  return guard<ecc_point_ref>(ecc_point_ref{nullptr}, [&]() -> ecc_point_ref {
    if (!valid_ref(point1) || !valid_ref(point2)) return fail(E_BADARG, ecc_point_ref{nullptr});
    return ecc_point_ref{new ecc_point_t(*as<ecc_point_t>(point1->opaque) - *as<ecc_point_t>(point2->opaque))};
  });
}

cmem_t ecc_point_get_x(ecc_point_ref* point) {
  return guard<cmem_t>(cmem_t{nullptr, 0}, [&]() -> cmem_t {
    if (!valid_ref(point)) return fail(E_BADARG, cmem_t{nullptr, 0});
    return copy_to_cmem(as<ecc_point_t>(point->opaque)->get_x().to_bin());
  });
}

cmem_t ecc_point_get_y(ecc_point_ref* point) {
  return guard<cmem_t>(cmem_t{nullptr, 0}, [&]() -> cmem_t {
    if (!valid_ref(point)) return fail(E_BADARG, cmem_t{nullptr, 0});
    return copy_to_cmem(as<ecc_point_t>(point->opaque)->get_y().to_bin());
  });
}

int ecc_point_is_zero(ecc_point_ref* point) {
  return guard_rv([&]() -> int {
    if (!valid_ref(point)) return 0;
    return as<ecc_point_t>(point->opaque)->is_infinity() ? 1 : 0;
  });
}

int ecc_point_equals(ecc_point_ref* point1, ecc_point_ref* point2) {
  return guard_rv([&]() -> int {
    if (!valid_ref(point1) || !valid_ref(point2)) return 0;
    return *as<ecc_point_t>(point1->opaque) == *as<ecc_point_t>(point2->opaque) ? 1 : 0;
  });
}

int ecc_verify_der(int curve_code, cmem_t pub_oct, cmem_t hash, cmem_t der_sig) {
  return guard_rv([&]() -> int {
    ecurve_t curve = ecurve_t::find(curve_code);
    if (!curve) return -1;
    ecc_point_t Q;
    if (Q.from_oct(curve, view(pub_oct))) return -2;
    ecc_pub_key_t pub(Q);
    return pub.verify(view(hash), view(der_sig)) ? -3 : 0;
  });
}

cmem_t bn_add(cmem_t a, cmem_t b) {
  return guard<cmem_t>(cmem_t{nullptr, 0}, [&]() -> cmem_t {
    bn_t c = bn_t::from_bin(view(a)) + bn_t::from_bin(view(b));
    return copy_to_cmem(c.to_bin());
  });
}

cmem_t ec_mod_add(ecurve_ref* curve, cmem_t a, cmem_t b) {
  return guard<cmem_t>(cmem_t{nullptr, 0}, [&]() -> cmem_t {
    if (!valid_ref(curve)) return fail(E_BADARG, cmem_t{nullptr, 0});
    const mod_t& q = as<ecurve_t>(curve->opaque)->order();
    bn_t c = (bn_t::from_bin(view(a)) + bn_t::from_bin(view(b))) % q;
    return copy_to_cmem(c.to_bin(q.get_bin_size()));
  });
}

cmem_t bn_from_int64(int64_t value) {
  return guard<cmem_t>(cmem_t{nullptr, 0}, [&]() -> cmem_t {
    bn_t bn;
    bn.set_int64(value);
    return copy_to_cmem(bn.to_bin());
  });
}

// ===========================================================================
// ECDSA 2P
// ===========================================================================

int mpc_ecdsa2p_dkg(job_2p_ref* j, int curve_code, mpc_ecdsa2pc_key_ref* k) {
  if (k) *k = mpc_ecdsa2pc_key_ref{nullptr};
  return guard_rv([&]() -> int {
    job_2p_t* job = job_of(j);
    ecurve_t curve = ecurve_t::find(curve_code);
    if (!job || !k || !curve) return E_BADARG;

    auto key = std::make_unique<ecdsa2pc::key_t>();
    if (error_t rv = ecdsa2pc::dkg(*job, curve, *key)) return rv;
    *k = mpc_ecdsa2pc_key_ref{key.release()};
    return 0;
  });
}

int mpc_ecdsa2p_refresh(job_2p_ref* j, mpc_ecdsa2pc_key_ref* k, mpc_ecdsa2pc_key_ref* nk) {
  if (nk) *nk = mpc_ecdsa2pc_key_ref{nullptr};
  return guard_rv([&]() -> int {
    job_2p_t* job = job_of(j);
    if (!job || !valid_ref(k) || !nk) return E_BADARG;

    auto new_key = std::make_unique<ecdsa2pc::key_t>();
    if (error_t rv = ecdsa2pc::refresh(*job, *as<ecdsa2pc::key_t>(k->opaque), *new_key)) return rv;
    *nk = mpc_ecdsa2pc_key_ref{new_key.release()};
    return 0;
  });
}

int mpc_ecdsa2p_sign(job_2p_ref* j, cmem_t sid_mem, mpc_ecdsa2pc_key_ref* k, cmems_t msgs, cmems_t* sigs) {
  if (sigs) *sigs = cmems_t{0, nullptr, nullptr};
  return guard_rv([&]() -> int {
    job_2p_t* job = job_of(j);
    if (!job || !valid_ref(k) || !sigs) return E_BADARG;
    *sigs = cmems_t{0, nullptr, nullptr};

    buf_t sid(view(sid_mem));
    std::vector<buf_t> owned_msgs = bufs_from_cmems(msgs);
    std::vector<mem_t> messages = buf_t::to_mems(owned_msgs);

    std::vector<buf_t> signatures;
    if (error_t rv = ecdsa2pc::sign_batch(*job, sid, *as<ecdsa2pc::key_t>(k->opaque), messages, signatures)) return rv;
    return copy_to_cmems_rv(buf_t::to_mems(signatures), sigs);
  });
}

void free_mpc_ecdsa2p_key(mpc_ecdsa2pc_key_ref key) { delete as<ecdsa2pc::key_t>(key.opaque); }

int mpc_ecdsa2p_key_get_role_index(mpc_ecdsa2pc_key_ref* key) {
  return guard_rv([&]() -> int {
    if (!valid_ref(key)) return -1;
    return static_cast<int>(as<ecdsa2pc::key_t>(key->opaque)->role);
  });
}

ecc_point_ref mpc_ecdsa2p_key_get_Q(mpc_ecdsa2pc_key_ref* key) {
  return guard<ecc_point_ref>(ecc_point_ref{nullptr}, [&]() -> ecc_point_ref {
    if (!valid_ref(key)) return fail(E_BADARG, ecc_point_ref{nullptr});
    return ecc_point_ref{new ecc_point_t(as<ecdsa2pc::key_t>(key->opaque)->Q)};
  });
}

cmem_t mpc_ecdsa2p_key_get_x_share(mpc_ecdsa2pc_key_ref* key) {
  return guard<cmem_t>(cmem_t{nullptr, 0}, [&]() -> cmem_t {
    if (!valid_ref(key)) return fail(E_BADARG, cmem_t{nullptr, 0});
    const auto& k = *as<ecdsa2pc::key_t>(key->opaque);
    return copy_to_cmem(k.x_share.to_bin(x_share_bin_size(k.x_share, k.curve)));
  });
}

int mpc_ecdsa2p_key_get_curve_code(mpc_ecdsa2pc_key_ref* key) {
  return guard_rv([&]() -> int {
    if (!valid_ref(key)) return -1;
    return as<ecdsa2pc::key_t>(key->opaque)->curve.get_openssl_code();
  });
}

// Layout (unchanged from the cgobinding era): [role:int32, curve, Q, x_share, c_key, paillier].
int serialize_mpc_ecdsa2p(mpc_ecdsa2pc_key_ref* k, cmems_t* ser) {
  if (ser) *ser = cmems_t{0, nullptr, nullptr};
  return guard_rv([&]() -> int {
    if (!valid_ref(k) || !ser) return E_BADARG;
    const auto& key = *as<ecdsa2pc::key_t>(k->opaque);
    int32_t role = static_cast<int32_t>(key.role);
    std::vector<buf_t> parts = {coinbase::ser(role),        coinbase::ser(key.curve), coinbase::ser(key.Q),
                                coinbase::ser(key.x_share), coinbase::ser(key.c_key), coinbase::ser(key.paillier)};
    return copy_to_cmems_rv(buf_t::to_mems(parts), ser);
  });
}

int deserialize_mpc_ecdsa2p(cmems_t sers, mpc_ecdsa2pc_key_ref* k) {
  if (k) *k = mpc_ecdsa2pc_key_ref{nullptr};
  return guard_rv([&]() -> int {
    if (!k) return E_BADARG;
    std::vector<buf_t> parts = bufs_from_cmems(sers);
    if (parts.size() != 6) return E_FORMAT;

    auto key = std::make_unique<ecdsa2pc::key_t>();
    int32_t role;
    if (coinbase::deser(parts[0], role) || (role != 0 && role != 1)) return E_FORMAT;
    key->role = static_cast<party_t>(role);
    if (coinbase::deser(parts[1], key->curve)) return E_FORMAT;
    if (coinbase::deser(parts[2], key->Q)) return E_FORMAT;
    if (coinbase::deser(parts[3], key->x_share)) return E_FORMAT;
    if (coinbase::deser(parts[4], key->c_key)) return E_FORMAT;
    if (coinbase::deser(parts[5], key->paillier)) return E_FORMAT;
    if (validate_ecdsa2p_key(*key)) return E_FORMAT;
    *k = mpc_ecdsa2pc_key_ref{key.release()};
    return 0;
  });
}

// ===========================================================================
// EC key 2P / Schnorr 2P
// ===========================================================================

int mpc_eckey_2p_dkg(job_2p_ref* j, int curve_code, mpc_eckey_2p_ref* k) {
  if (k) *k = mpc_eckey_2p_ref{nullptr};
  return guard_rv([&]() -> int {
    job_2p_t* job = job_of(j);
    ecurve_t curve = ecurve_t::find(curve_code);
    if (!job || !k || !curve) return E_BADARG;

    auto key = std::make_unique<eckey::key_share_2p_t>();
    buf_t sid;
    if (error_t rv = eckey::key_share_2p_t::dkg(*job, curve, *key, sid)) return rv;
    *k = mpc_eckey_2p_ref{key.release()};
    return 0;
  });
}

int mpc_schnorr2p_eddsa_sign(job_2p_ref* j, mpc_eckey_2p_ref* k, cmem_t msg, cmem_t* sig_out) {
  if (sig_out) *sig_out = cmem_t{nullptr, 0};
  return guard_rv([&]() -> int {
    job_2p_t* job = job_of(j);
    if (!job || !valid_ref(k) || !sig_out) return E_BADARG;
    *sig_out = cmem_t{nullptr, 0};

    buf_t sig;
    if (error_t rv = schnorr2p::sign(*job, *as<eckey::key_share_2p_t>(k->opaque), view(msg), sig,
                                     schnorr2p::variant_e::EdDSA))
      return rv;
    return copy_to_cmem_rv(sig, sig_out);
  });
}

void free_mpc_eckey_2p(mpc_eckey_2p_ref key) { delete as<eckey::key_share_2p_t>(key.opaque); }

int mpc_eckey_2p_get_role_index(mpc_eckey_2p_ref* key) {
  return guard_rv([&]() -> int {
    if (!valid_ref(key)) return -1;
    return static_cast<int>(as<eckey::key_share_2p_t>(key->opaque)->role);
  });
}

ecc_point_ref mpc_eckey_2p_get_Q(mpc_eckey_2p_ref* key) {
  return guard<ecc_point_ref>(ecc_point_ref{nullptr}, [&]() -> ecc_point_ref {
    if (!valid_ref(key)) return fail(E_BADARG, ecc_point_ref{nullptr});
    return ecc_point_ref{new ecc_point_t(as<eckey::key_share_2p_t>(key->opaque)->Q)};
  });
}

cmem_t mpc_eckey_2p_get_x_share(mpc_eckey_2p_ref* key) {
  return guard<cmem_t>(cmem_t{nullptr, 0}, [&]() -> cmem_t {
    if (!valid_ref(key)) return fail(E_BADARG, cmem_t{nullptr, 0});
    const auto& k = *as<eckey::key_share_2p_t>(key->opaque);
    return copy_to_cmem(k.x_share.to_bin(x_share_bin_size(k.x_share, k.curve)));
  });
}

int mpc_eckey_2p_get_curve_code(mpc_eckey_2p_ref* key) {
  return guard_rv([&]() -> int {
    if (!valid_ref(key)) return -1;
    return as<eckey::key_share_2p_t>(key->opaque)->curve.get_openssl_code();
  });
}

// Layout: [role:int32, curve, Q, x_share].
int serialize_mpc_eckey_2p(mpc_eckey_2p_ref* k, cmems_t* ser) {
  if (ser) *ser = cmems_t{0, nullptr, nullptr};
  return guard_rv([&]() -> int {
    if (!valid_ref(k) || !ser) return E_BADARG;
    const auto& key = *as<eckey::key_share_2p_t>(k->opaque);
    int32_t role = static_cast<int32_t>(key.role);
    std::vector<buf_t> parts = {coinbase::ser(role), coinbase::ser(key.curve), coinbase::ser(key.Q),
                                coinbase::ser(key.x_share)};
    return copy_to_cmems_rv(buf_t::to_mems(parts), ser);
  });
}

int deserialize_mpc_eckey_2p(cmems_t sers, mpc_eckey_2p_ref* k) {
  if (k) *k = mpc_eckey_2p_ref{nullptr};
  return guard_rv([&]() -> int {
    if (!k) return E_BADARG;
    std::vector<buf_t> parts = bufs_from_cmems(sers);
    if (parts.size() != 4) return E_FORMAT;

    auto key = std::make_unique<eckey::key_share_2p_t>();
    int32_t role;
    if (coinbase::deser(parts[0], role) || (role != 0 && role != 1)) return E_FORMAT;
    key->role = static_cast<party_t>(role);
    if (coinbase::deser(parts[1], key->curve)) return E_FORMAT;
    if (coinbase::deser(parts[2], key->Q)) return E_FORMAT;
    if (coinbase::deser(parts[3], key->x_share)) return E_FORMAT;
    if (validate_eckey_2p_key(*key)) return E_FORMAT;
    *k = mpc_eckey_2p_ref{key.release()};
    return 0;
  });
}

// ===========================================================================
// EC key MP, ECDSA MP, EdDSA MP
// ===========================================================================

int mpc_eckey_mp_dkg(job_mp_ref* j, ecurve_ref* curve, mpc_eckey_mp_ref* k) {
  if (k) *k = mpc_eckey_mp_ref{nullptr};
  return guard_rv([&]() -> int {
    job_mp_t* job = job_of(j);
    if (!job || !valid_ref(curve) || !k) return E_BADARG;

    auto key = std::make_unique<eckey::key_share_mp_t>();
    buf_t sid;
    if (error_t rv = eckey::key_share_mp_t::dkg(*job, *as<ecurve_t>(curve->opaque), *key, sid)) return rv;
    *k = mpc_eckey_mp_ref{key.release()};
    return 0;
  });
}

int mpc_eckey_mp_refresh(job_mp_ref* j, cmem_t sid_mem, mpc_eckey_mp_ref* k, mpc_eckey_mp_ref* nk) {
  if (nk) *nk = mpc_eckey_mp_ref{nullptr};
  return guard_rv([&]() -> int {
    job_mp_t* job = job_of(j);
    if (!job || !valid_ref(k) || !nk) return E_BADARG;

    auto new_key = std::make_unique<eckey::key_share_mp_t>();
    buf_t sid(view(sid_mem));
    if (error_t rv = eckey::key_share_mp_t::refresh(*job, sid, *as<eckey::key_share_mp_t>(k->opaque), *new_key))
      return rv;
    *nk = mpc_eckey_mp_ref{new_key.release()};
    return 0;
  });
}

void free_mpc_eckey_mp(mpc_eckey_mp_ref key) { delete as<eckey::key_share_mp_t>(key.opaque); }

int mpc_eckey_mp_get_party_name(mpc_eckey_mp_ref* k, cmem_t* party_name) {
  if (party_name) *party_name = cmem_t{nullptr, 0};
  return guard_rv([&]() -> int {
    if (!valid_ref(k) || !party_name) return 1;
    return copy_to_cmem_rv(mem_t(as<eckey::key_share_mp_t>(k->opaque)->party_name), party_name);
  });
}

int mpc_eckey_mp_get_x_share(mpc_eckey_mp_ref* k, cmem_t* x_share) {
  if (x_share) *x_share = cmem_t{nullptr, 0};
  return guard_rv([&]() -> int {
    if (!valid_ref(k) || !x_share) return 1;
    const auto& key = *as<eckey::key_share_mp_t>(k->opaque);
    return copy_to_cmem_rv(key.x_share.to_bin(key.curve.order().get_bin_size()), x_share);
  });
}

ecc_point_ref mpc_eckey_mp_get_Q(mpc_eckey_mp_ref* k) {
  return guard<ecc_point_ref>(ecc_point_ref{nullptr}, [&]() -> ecc_point_ref {
    if (!valid_ref(k)) return fail(E_BADARG, ecc_point_ref{nullptr});
    return ecc_point_ref{new ecc_point_t(as<eckey::key_share_mp_t>(k->opaque)->Q)};
  });
}

ecurve_ref mpc_eckey_mp_get_curve(mpc_eckey_mp_ref* k) {
  return guard<ecurve_ref>(ecurve_ref{nullptr}, [&]() -> ecurve_ref {
    if (!valid_ref(k)) return fail(E_BADARG, ecurve_ref{nullptr});
    return ecurve_ref{new ecurve_t(as<eckey::key_share_mp_t>(k->opaque)->curve)};
  });
}

// Layout: [x_share, Q, Qis, curve, party_name].
int serialize_mpc_eckey_mp(mpc_eckey_mp_ref* k, cmems_t* ser) {
  if (ser) *ser = cmems_t{0, nullptr, nullptr};
  return guard_rv([&]() -> int {
    if (!valid_ref(k) || !ser) return E_BADARG;
    const auto& key = *as<eckey::key_share_mp_t>(k->opaque);
    std::vector<buf_t> parts = {coinbase::ser(key.x_share), coinbase::ser(key.Q), coinbase::ser(key.Qis),
                                coinbase::ser(key.curve), coinbase::ser(key.party_name)};
    return copy_to_cmems_rv(buf_t::to_mems(parts), ser);
  });
}

int deserialize_mpc_eckey_mp(cmems_t sers, mpc_eckey_mp_ref* k) {
  if (k) *k = mpc_eckey_mp_ref{nullptr};
  return guard_rv([&]() -> int {
    if (!k) return E_BADARG;
    std::vector<buf_t> parts = bufs_from_cmems(sers);
    if (parts.size() != 5) return E_FORMAT;

    auto key = std::make_unique<eckey::key_share_mp_t>();
    if (coinbase::deser(parts[0], key->x_share)) return E_FORMAT;
    if (coinbase::deser(parts[1], key->Q)) return E_FORMAT;
    if (coinbase::deser(parts[2], key->Qis)) return E_FORMAT;
    if (coinbase::deser(parts[3], key->curve)) return E_FORMAT;
    if (coinbase::deser(parts[4], key->party_name)) return E_FORMAT;
    if (validate_eckey_mp_key(*key)) return E_FORMAT;
    *k = mpc_eckey_mp_ref{key.release()};
    return 0;
  });
}

int mpc_ecdsampc_sign(job_mp_ref* j, mpc_eckey_mp_ref* k, cmem_t msg, int sig_receiver, cmem_t* sig_out) {
  if (sig_out) *sig_out = cmem_t{nullptr, 0};
  return guard_rv([&]() -> int {
    job_mp_t* job = job_of(j);
    if (!job || !valid_ref(k) || !sig_out) return E_BADARG;
    *sig_out = cmem_t{nullptr, 0};

    buf_t sig;
    if (error_t rv =
            ecdsampc::sign(*job, *as<ecdsampc::key_t>(k->opaque), view(msg), party_idx_t(sig_receiver), sig))
      return rv;
    return copy_to_cmem_rv(sig, sig_out);
  });
}

int mpc_eddsampc_sign(job_mp_ref* j, mpc_eckey_mp_ref* k, cmem_t msg, int sig_receiver, cmem_t* sig_out) {
  if (sig_out) *sig_out = cmem_t{nullptr, 0};
  return guard_rv([&]() -> int {
    job_mp_t* job = job_of(j);
    if (!job || !valid_ref(k) || !sig_out) return E_BADARG;
    *sig_out = cmem_t{nullptr, 0};

    buf_t sig;
    if (error_t rv =
            eddsampc::sign(*job, *as<eddsampc::key_t>(k->opaque), view(msg), party_idx_t(sig_receiver), sig))
      return rv;
    return copy_to_cmem_rv(sig, sig_out);
  });
}

// ===========================================================================
// ZK and agree-random
// ===========================================================================

int zk_dl_prove(ecc_point_ref* Q, cmem_t w_mem, cmem_t sid_mem, uint64_t aux, cmem_t* proof_out) {
  if (proof_out) *proof_out = cmem_t{nullptr, 0};
  return guard_rv([&]() -> int {
    if (!valid_ref(Q) || !proof_out) return E_BADARG;
    coinbase::zk::uc_dl_t zk;
    zk.prove(*as<ecc_point_t>(Q->opaque), bn_t::from_bin(view(w_mem)), view(sid_mem), aux);
    return copy_to_cmem_rv(coinbase::ser(zk), proof_out);
  });
}

int zk_dl_verify(ecc_point_ref* Q, cmem_t proof, cmem_t sid_mem, uint64_t aux) {
  return guard_rv([&]() -> int {
    if (!valid_ref(Q)) return E_BADARG;
    coinbase::zk::uc_dl_t zk;
    if (error_t rv = coinbase::deser(view(proof), zk)) return rv;
    return zk.verify(*as<ecc_point_t>(Q->opaque), view(sid_mem), aux);
  });
}

int mpc_agree_random(job_2p_ref* j, int bit_len, cmem_t* out) {
  if (out) *out = cmem_t{nullptr, 0};
  return guard_rv([&]() -> int {
    job_2p_t* job = job_of(j);
    if (!job || !out || bit_len <= 0) return NETWORK_PARAM_ERROR;
    buf_t out_buf;
    if (error_t rv = agree_random(*job, bit_len, out_buf)) return rv;
    return copy_to_cmem_rv(out_buf, out);
  });
}

// ===========================================================================
// PVE (batch, single recipient, built-in ECIES P-256 base PKE)
// ===========================================================================

namespace {

// Maps an OpenSSL curve NID to the public API curve id; false when unsupported.
bool pve_curve(int curve_code, coinbase::api::curve_id& out) {
  ecurve_t curve = ecurve_t::find(curve_code);
  if (curve == curve_secp256k1) out = coinbase::api::curve_id::secp256k1;
  else if (curve == curve_p256) out = coinbase::api::curve_id::p256;
  else if (curve == curve_ed25519) out = coinbase::api::curve_id::ed25519;
  else return false;
  return true;
}

std::vector<mem_t> mems_view(const std::vector<buf_t>& bufs) {
  std::vector<mem_t> out;
  out.reserve(bufs.size());
  for (const auto& b : bufs) out.emplace_back(b);
  return out;
}

}  // namespace

int pve_generate_ecies_p256_keypair(cmem_t* ek, cmem_t* dk) {
  if (ek) *ek = cmem_t{nullptr, 0};
  if (dk) *dk = cmem_t{nullptr, 0};
  return guard_rv([&]() -> int {
    if (!ek || !dk) return E_BADARG;
    buf_t ek_buf, dk_buf;
    if (error_t rv = coinbase::api::pve::generate_base_pke_ecies_p256_keypair(ek_buf, dk_buf)) return rv;
    if (int rv = copy_to_cmem_rv(ek_buf, ek)) return rv;
    if (int rv = copy_to_cmem_rv(dk_buf, dk)) {
      std::free(ek->data);
      *ek = cmem_t{nullptr, 0};
      return rv;
    }
    return 0;
  });
}

int pve_batch_encrypt(int curve_code, cmem_t ek, cmem_t label, cmems_t xs, cmem_t* ciphertext) {
  if (ciphertext) *ciphertext = cmem_t{nullptr, 0};
  return guard_rv([&]() -> int {
    coinbase::api::curve_id curve;
    if (!ciphertext || !pve_curve(curve_code, curve)) return E_BADARG;
    std::vector<buf_t> x_bufs = bufs_from_cmems(xs);
    if (x_bufs.empty()) return E_BADARG;
    buf_t ct;
    if (error_t rv = coinbase::api::pve::encrypt_batch(curve, view(ek), view(label), mems_view(x_bufs), ct)) return rv;
    return copy_to_cmem_rv(ct, ciphertext);
  });
}

int pve_batch_verify(int curve_code, cmem_t ek, cmem_t ciphertext, cmems_t Qs_compressed, cmem_t label) {
  return guard_rv([&]() -> int {
    coinbase::api::curve_id curve;
    if (!pve_curve(curve_code, curve)) return E_BADARG;
    std::vector<buf_t> q_bufs = bufs_from_cmems(Qs_compressed);
    if (q_bufs.empty()) return E_BADARG;
    // Accept points as serialized by this layer (ecc_point_to_bytes) as well as
    // raw compressed encodings: re-encode the former to what the PVE API parses.
    // A serialized point tagged with another curve is rejected rather than reinterpreted.
    const ecurve_t icurve = ecurve_t::find(curve_code);
    for (auto& q : q_bufs) {
      ecc_point_t point;
      if (coinbase::deser(mem_t(q), point)) continue;
      if (point.get_curve() != icurve) return E_BADARG;
      q = point.to_compressed_bin();
    }
    return coinbase::api::pve::verify_batch(curve, view(ek), view(ciphertext), mems_view(q_bufs), view(label));
  });
}

int pve_batch_decrypt(int curve_code, cmem_t dk, cmem_t ek, cmem_t ciphertext, cmem_t label, cmems_t* xs) {
  if (xs) *xs = cmems_t{0, nullptr, nullptr};
  return guard_rv([&]() -> int {
    coinbase::api::curve_id curve;
    if (!xs || !pve_curve(curve_code, curve)) return E_BADARG;
    std::vector<buf_t> out;
    if (error_t rv = coinbase::api::pve::decrypt_batch(curve, view(dk), view(ek), view(ciphertext), view(label), out))
      return rv;
    return copy_to_cmems_rv(mems_view(out), xs);
  });
}

// ===========================================================================
// Access-structure (AC) keys: dkg / refresh / sign / reshare
// ===========================================================================
// Key blobs are the library's own v2 AC blobs (same bytes as the public C API), so a share made here can be used by
// any other binding of the library. ECDSA-MP on secp256k1 / P-256, EdDSA-MP on Ed25519.

namespace {

struct api_job_t {
  std::vector<std::string_view> names;
  std::unique_ptr<coinbase::api::job_mp_t> job;
};

error_t to_api_job(job_mp_ref* j, api_job_t& out) {
  job_mp_t* job = job_of(j);
  if (!job) return E_BADARG;
  auto* transport = static_cast<ts_job_mp_t*>(job)->api_transport();
  if (!transport) return E_BADARG;
  for (const auto& name : job->get_names()) out.names.emplace_back(name);
  out.job.reset(new coinbase::api::job_mp_t{job->get_party_idx(), out.names, *transport});
  return SUCCESS;
}

error_t decode_ac(cmem_t in, coinbase::api::access_structure_t& out) {
  return cbmpc_ts::access_structure_decoder_t(view(in)).decode(out);
}

// Party names passed as cmems_t of UTF-8 strings; `storage` owns the bytes the views point into.
std::vector<std::string_view> names_view(cmems_t names, std::vector<std::string>& storage) {
  storage.clear();
  for (const auto& b : bufs_from_cmems(names)) storage.emplace_back(reinterpret_cast<const char*>(b.data()), b.size());
  return std::vector<std::string_view>(storage.begin(), storage.end());
}

bool blob_is_eddsa(mem_t blob) {
  dylog_disable_scope_t quiet;  // an ECDSA blob failing this probe is expected, not an error to log
  buf_t Q;
  return coinbase::api::eddsa_mp::get_public_key_compressed(blob, Q) == SUCCESS;
}

// Accepts the library's compressed encoding or the SEC1 uncompressed 04||x||y form the 2P getters return
// (for Ed25519, x and y are the big-endian affine coordinates). Returns the library's compressed encoding.
error_t to_compressed_public_key(coinbase::api::curve_id cid, mem_t in, buf_t& out) {
  const ecurve_t curve = cid == coinbase::api::curve_id::ed25519 ? curve_ed25519
                         : cid == coinbase::api::curve_id::p256  ? curve_p256
                                                                 : curve_secp256k1;
  buf_t bin(in);
  if (cid == coinbase::api::curve_id::ed25519 && in.size == 65 && in.data[0] == 0x04) {
    bin = buf_t(32);
    for (int i = 0; i < 32; i++) bin[i] = in.data[64 - i];  // y, little-endian
    bin[31] = uint8_t((bin[31] & 0x7f) | ((in.data[32] & 1) << 7));  // sign of x
  }
  ecc_point_t Q;
  if (error_t rv = Q.from_bin(curve, bin)) return rv;
  if (curve.check(Q) || Q.is_infinity()) return E_FORMAT;
  out = Q.to_compressed_bin();
  return SUCCESS;
}

}  // namespace

int mpc_ac_dkg(job_mp_ref* j, int curve_code, cmem_t access_structure, cmems_t quorum_names, cmem_t* key_blob) {
  if (key_blob) *key_blob = cmem_t{nullptr, 0};
  return guard_rv([&]() -> int {
    coinbase::api::curve_id cid;
    api_job_t aj;
    coinbase::api::access_structure_t ac;
    if (!key_blob || !pve_curve(curve_code, cid) || to_api_job(j, aj) || decode_ac(access_structure, ac))
      return E_BADARG;
    std::vector<std::string> storage;
    const auto quorum = names_view(quorum_names, storage);
    buf_t sid, out;
    const error_t rv = cid == coinbase::api::curve_id::ed25519
                           ? coinbase::api::eddsa_mp::dkg_ac(*aj.job, cid, sid, ac, quorum, out)
                           : coinbase::api::ecdsa_mp::dkg_ac(*aj.job, cid, sid, ac, quorum, out);
    if (rv) return rv;
    return copy_to_cmem_rv(out, key_blob);
  });
}

int mpc_ac_refresh(job_mp_ref* j, cmem_t key_blob, cmem_t access_structure, cmems_t quorum_names,
                   cmem_t* new_key_blob) {
  if (new_key_blob) *new_key_blob = cmem_t{nullptr, 0};
  return guard_rv([&]() -> int {
    api_job_t aj;
    coinbase::api::access_structure_t ac;
    if (!new_key_blob || to_api_job(j, aj) || decode_ac(access_structure, ac)) return E_BADARG;
    std::vector<std::string> storage;
    const auto quorum = names_view(quorum_names, storage);
    buf_t sid, out;
    const error_t rv = blob_is_eddsa(view(key_blob))
                           ? coinbase::api::eddsa_mp::refresh_ac(*aj.job, sid, view(key_blob), ac, quorum, out)
                           : coinbase::api::ecdsa_mp::refresh_ac(*aj.job, sid, view(key_blob), ac, quorum, out);
    if (rv) return rv;
    return copy_to_cmem_rv(out, new_key_blob);
  });
}

int mpc_ac_sign(job_mp_ref* j, cmem_t key_blob, cmem_t access_structure, cmem_t msg, int sig_receiver, cmem_t* sig) {
  if (sig) *sig = cmem_t{nullptr, 0};
  return guard_rv([&]() -> int {
    api_job_t aj;
    coinbase::api::access_structure_t ac;
    if (!sig || to_api_job(j, aj) || decode_ac(access_structure, ac)) return E_BADARG;
    buf_t out;
    const error_t rv =
        blob_is_eddsa(view(key_blob))
            ? coinbase::api::eddsa_mp::sign_ac(*aj.job, view(key_blob), ac, view(msg), sig_receiver, out)
            : coinbase::api::ecdsa_mp::sign_ac(*aj.job, view(key_blob), ac, view(msg), sig_receiver, out);
    if (rv) return rv;
    return copy_to_cmem_rv(out, sig);
  });
}

int mpc_ac_reshare_from_additive(job_mp_ref* j, int curve_code, cmem_t public_key, cmems_t dealer_names,
                                 cmem_t additive_share, cmem_t new_access_structure, cmem_t* new_key_blob) {
  if (new_key_blob) *new_key_blob = cmem_t{nullptr, 0};
  return guard_rv([&]() -> int {
    coinbase::api::curve_id cid;
    api_job_t aj;
    coinbase::api::access_structure_t ac;
    if (!new_key_blob || !pve_curve(curve_code, cid) || to_api_job(j, aj) || decode_ac(new_access_structure, ac))
      return E_BADARG;
    buf_t Q;
    if (error_t rv = to_compressed_public_key(cid, view(public_key), Q)) return rv;
    std::vector<std::string> storage;
    const auto dealers = names_view(dealer_names, storage);
    buf_t sid, out;
    const error_t rv =
        cid == coinbase::api::curve_id::ed25519
            ? coinbase::api::eddsa_mp::reshare_from_additive(*aj.job, cid, sid, Q, dealers, view(additive_share), ac,
                                                             out)
            : coinbase::api::ecdsa_mp::reshare_from_additive(*aj.job, cid, sid, Q, dealers, view(additive_share), ac,
                                                             out);
    if (rv) return rv;
    return copy_to_cmem_rv(out, new_key_blob);
  });
}

int mpc_ac_to_additive_share(cmem_t key_blob, cmem_t access_structure, cmems_t quorum_names, cmem_t* additive_share) {
  if (additive_share) *additive_share = cmem_t{nullptr, 0};
  return guard_rv([&]() -> int {
    coinbase::api::access_structure_t ac;
    if (!additive_share || decode_ac(access_structure, ac)) return E_BADARG;
    std::vector<std::string> storage;
    const auto quorum = names_view(quorum_names, storage);
    buf_t x;
    const error_t rv = blob_is_eddsa(view(key_blob))
                           ? coinbase::api::eddsa_mp::ac_key_to_additive_share(view(key_blob), ac, quorum, x)
                           : coinbase::api::ecdsa_mp::ac_key_to_additive_share(view(key_blob), ac, quorum, x);
    if (rv) return rv;
    return copy_to_cmem_rv(x, additive_share);
  });
}

int mpc_ac_key_info(cmem_t key_blob, cmem_t* public_key, cmem_t* public_share) {
  if (public_key) *public_key = cmem_t{nullptr, 0};
  if (public_share) *public_share = cmem_t{nullptr, 0};
  return guard_rv([&]() -> int {
    if (!public_key || !public_share) return E_BADARG;
    const bool eddsa = blob_is_eddsa(view(key_blob));
    buf_t Q, Qi;
    error_t rv = eddsa ? coinbase::api::eddsa_mp::get_public_key_compressed(view(key_blob), Q)
                       : coinbase::api::ecdsa_mp::get_public_key_compressed(view(key_blob), Q);
    if (rv) return rv;
    rv = eddsa ? coinbase::api::eddsa_mp::get_public_share_compressed(view(key_blob), Qi)
               : coinbase::api::ecdsa_mp::get_public_share_compressed(view(key_blob), Qi);
    if (rv) return rv;
    if (int r = copy_to_cmem_rv(Q, public_key)) return r;
    if (int r = copy_to_cmem_rv(Qi, public_share)) {
      std::free(public_key->data);
      *public_key = cmem_t{nullptr, 0};
      return r;
    }
    return 0;
  });
}
