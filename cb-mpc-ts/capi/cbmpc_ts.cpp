#include "cbmpc_ts.h"

#include <cstring>
#include <iostream>
#include <memory>
#include <set>
#include <string_view>
#include <vector>

#include <cbmpc/core/buf.h>
#include <cbmpc/internal/crypto/base.h>
#include <cbmpc/internal/protocol/agree_random.h>
#include <cbmpc/internal/protocol/ec_dkg.h>
#include <cbmpc/internal/protocol/ecdsa_2p.h>
#include <cbmpc/internal/protocol/ecdsa_mp.h>
#include <cbmpc/internal/protocol/eddsa.h>
#include <cbmpc/internal/protocol/mpc_job.h>
#include <cbmpc/internal/protocol/schnorr_2p.h>
#include <cbmpc/internal/zk/zk_ec.h>

using namespace coinbase;
using namespace coinbase::crypto;
using namespace coinbase::mpc;

// ===========================================================================
// cmem helpers
// ===========================================================================

namespace {

mem_t view(cmem_t cmem) { return mem_t(cmem.data, cmem.size); }

cmem_t copy_to_cmem(mem_t mem) {
  cmem_t out{nullptr, mem.size};
  if (mem.size > 0) {
    out.data = static_cast<uint8_t*>(std::malloc(mem.size));
    if (!out.data) return cmem_t{nullptr, 0};
    std::memmove(out.data, mem.data, mem.size);
  }
  return out;
}

std::vector<buf_t> bufs_from_cmems(cmems_t cmems) {
  std::vector<buf_t> out;
  if (cmems.count <= 0 || !cmems.sizes) return out;
  out.reserve(cmems.count);
  int offset = 0;
  for (int i = 0; i < cmems.count; i++) {
    const int sz = cmems.sizes[i];
    out.emplace_back(mem_t(cmems.data + offset, sz));
    offset += sz;
  }
  return out;
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
      std::free(cmsg.data);
      return error_t(rv);
    }
    msg = buf_t(view(cmsg));
    std::free(cmsg.data);
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
    if (!rv) msgs = bufs_from_cmems(cmsgs);
    std::free(cmsgs.data);
    std::free(cmsgs.sizes);
    return error_t(rv);
  }

 private:
  const data_transport_callbacks_t callbacks_;
  void* const ctx_;
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

}  // namespace

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
    auto job = std::make_unique<job_mp_t>(party_index, std::move(names), transport);
    return new job_mp_ref{job.release()};
  } catch (const std::exception& e) {
    std::cerr << "new_job_mp: " << e.what() << std::endl;
    return nullptr;
  }
}

void free_job_mp(job_mp_ref* ptr) {
  if (!ptr) return;
  delete as<job_mp_t>(ptr->opaque);
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

mpc_party_set_ref new_party_set(void) { return mpc_party_set_ref{new party_set_t()}; }

void party_set_add(mpc_party_set_ref* set, int party_idx) {
  if (valid_ref(set)) as<party_set_t>(set->opaque)->add(party_idx);
}

void free_party_set(mpc_party_set_ref ctx) { delete as<party_set_t>(ctx.opaque); }

// ===========================================================================
// Curves, points and scalars
// ===========================================================================

ecurve_ref new_ecurve(int curve_code) {
  ecurve_t curve = ecurve_t::find(curve_code);
  if (!curve) return ecurve_ref{nullptr};
  return ecurve_ref{new ecurve_t(curve)};
}

void free_ecurve(ecurve_ref ref) { delete as<ecurve_t>(ref.opaque); }

ecc_point_ref ecurve_generator(ecurve_ref* curve) {
  if (!valid_ref(curve)) return ecc_point_ref{nullptr};
  return ecc_point_ref{new ecc_point_t(as<ecurve_t>(curve->opaque)->generator())};
}

cmem_t ecurve_order(ecurve_ref* curve) {
  if (!valid_ref(curve)) return cmem_t{nullptr, 0};
  bn_t order = as<ecurve_t>(curve->opaque)->order();
  return copy_to_cmem(order.to_bin());
}

int ecurve_get_curve_code(ecurve_ref* curve) {
  if (!valid_ref(curve)) return -1;
  return as<ecurve_t>(curve->opaque)->get_openssl_code();
}

cmem_t ecurve_random_scalar(ecurve_ref* curve) {
  if (!valid_ref(curve)) return cmem_t{nullptr, 0};
  const ecurve_t& c = *as<ecurve_t>(curve->opaque);
  bn_t k = c.get_random_value();
  return copy_to_cmem(k.to_bin(c.order().get_bin_size()));
}

ecc_point_ref ecurve_mul_generator(ecurve_ref* curve, cmem_t scalar) {
  if (!valid_ref(curve)) return ecc_point_ref{nullptr};
  bn_t k = bn_t::from_bin(view(scalar));
  return ecc_point_ref{new ecc_point_t(as<ecurve_t>(curve->opaque)->mul_to_generator(k))};
}

void free_ecc_point(ecc_point_ref ref) { delete as<ecc_point_t>(ref.opaque); }

ecc_point_ref ecc_point_from_bytes(cmem_t point_bytes) {
  auto point = std::make_unique<ecc_point_t>();
  if (coinbase::deser(view(point_bytes), *point)) return ecc_point_ref{nullptr};
  return ecc_point_ref{point.release()};
}

cmem_t ecc_point_to_bytes(ecc_point_ref* point) {
  if (!valid_ref(point)) return cmem_t{nullptr, 0};
  return copy_to_cmem(coinbase::ser(*as<ecc_point_t>(point->opaque)));
}

ecc_point_ref ecc_point_multiply(ecc_point_ref* point, cmem_t scalar) {
  if (!valid_ref(point)) return ecc_point_ref{nullptr};
  bn_t k = bn_t::from_bin(view(scalar));
  return ecc_point_ref{new ecc_point_t(k * (*as<ecc_point_t>(point->opaque)))};
}

ecc_point_ref ecc_point_add(ecc_point_ref* point1, ecc_point_ref* point2) {
  if (!valid_ref(point1) || !valid_ref(point2)) return ecc_point_ref{nullptr};
  return ecc_point_ref{new ecc_point_t(*as<ecc_point_t>(point1->opaque) + *as<ecc_point_t>(point2->opaque))};
}

ecc_point_ref ecc_point_subtract(ecc_point_ref* point1, ecc_point_ref* point2) {
  if (!valid_ref(point1) || !valid_ref(point2)) return ecc_point_ref{nullptr};
  return ecc_point_ref{new ecc_point_t(*as<ecc_point_t>(point1->opaque) - *as<ecc_point_t>(point2->opaque))};
}

cmem_t ecc_point_get_x(ecc_point_ref* point) {
  if (!valid_ref(point)) return cmem_t{nullptr, 0};
  return copy_to_cmem(as<ecc_point_t>(point->opaque)->get_x().to_bin());
}

cmem_t ecc_point_get_y(ecc_point_ref* point) {
  if (!valid_ref(point)) return cmem_t{nullptr, 0};
  return copy_to_cmem(as<ecc_point_t>(point->opaque)->get_y().to_bin());
}

int ecc_point_is_zero(ecc_point_ref* point) {
  if (!valid_ref(point)) return 0;
  return as<ecc_point_t>(point->opaque)->is_infinity() ? 1 : 0;
}

int ecc_point_equals(ecc_point_ref* point1, ecc_point_ref* point2) {
  if (!valid_ref(point1) || !valid_ref(point2)) return 0;
  return *as<ecc_point_t>(point1->opaque) == *as<ecc_point_t>(point2->opaque) ? 1 : 0;
}

int ecc_verify_der(int curve_code, cmem_t pub_oct, cmem_t hash, cmem_t der_sig) {
  ecurve_t curve = ecurve_t::find(curve_code);
  if (!curve) return -1;
  ecc_point_t Q;
  if (Q.from_oct(curve, view(pub_oct))) return -2;
  ecc_pub_key_t pub(Q);
  return pub.verify(view(hash), view(der_sig)) ? -3 : 0;
}

cmem_t bn_add(cmem_t a, cmem_t b) {
  bn_t c = bn_t::from_bin(view(a)) + bn_t::from_bin(view(b));
  return copy_to_cmem(c.to_bin());
}

cmem_t ec_mod_add(ecurve_ref* curve, cmem_t a, cmem_t b) {
  if (!valid_ref(curve)) return cmem_t{nullptr, 0};
  const mod_t& q = as<ecurve_t>(curve->opaque)->order();
  bn_t c = (bn_t::from_bin(view(a)) + bn_t::from_bin(view(b))) % q;
  return copy_to_cmem(c.to_bin(q.get_bin_size()));
}

cmem_t bn_from_int64(int64_t value) {
  bn_t bn;
  bn.set_int64(value);
  return copy_to_cmem(bn.to_bin());
}

// ===========================================================================
// ECDSA 2P
// ===========================================================================

int mpc_ecdsa2p_dkg(job_2p_ref* j, int curve_code, mpc_ecdsa2pc_key_ref* k) {
  job_2p_t* job = job_of(j);
  ecurve_t curve = ecurve_t::find(curve_code);
  if (!job || !k || !curve) return E_BADARG;

  auto key = std::make_unique<ecdsa2pc::key_t>();
  if (error_t rv = ecdsa2pc::dkg(*job, curve, *key)) return rv;
  *k = mpc_ecdsa2pc_key_ref{key.release()};
  return 0;
}

int mpc_ecdsa2p_refresh(job_2p_ref* j, mpc_ecdsa2pc_key_ref* k, mpc_ecdsa2pc_key_ref* nk) {
  job_2p_t* job = job_of(j);
  if (!job || !valid_ref(k) || !nk) return E_BADARG;

  auto new_key = std::make_unique<ecdsa2pc::key_t>();
  if (error_t rv = ecdsa2pc::refresh(*job, *as<ecdsa2pc::key_t>(k->opaque), *new_key)) return rv;
  *nk = mpc_ecdsa2pc_key_ref{new_key.release()};
  return 0;
}

int mpc_ecdsa2p_sign(job_2p_ref* j, cmem_t sid_mem, mpc_ecdsa2pc_key_ref* k, cmems_t msgs, cmems_t* sigs) {
  job_2p_t* job = job_of(j);
  if (!job || !valid_ref(k) || !sigs) return E_BADARG;
  *sigs = cmems_t{0, nullptr, nullptr};

  buf_t sid(view(sid_mem));
  std::vector<buf_t> owned_msgs = bufs_from_cmems(msgs);
  std::vector<mem_t> messages = buf_t::to_mems(owned_msgs);

  std::vector<buf_t> signatures;
  if (error_t rv = ecdsa2pc::sign_batch(*job, sid, *as<ecdsa2pc::key_t>(k->opaque), messages, signatures)) return rv;
  *sigs = copy_to_cmems(buf_t::to_mems(signatures));
  return 0;
}

void free_mpc_ecdsa2p_key(mpc_ecdsa2pc_key_ref key) { delete as<ecdsa2pc::key_t>(key.opaque); }

int mpc_ecdsa2p_key_get_role_index(mpc_ecdsa2pc_key_ref* key) {
  if (!valid_ref(key)) return -1;
  return static_cast<int>(as<ecdsa2pc::key_t>(key->opaque)->role);
}

ecc_point_ref mpc_ecdsa2p_key_get_Q(mpc_ecdsa2pc_key_ref* key) {
  if (!valid_ref(key)) return ecc_point_ref{nullptr};
  return ecc_point_ref{new ecc_point_t(as<ecdsa2pc::key_t>(key->opaque)->Q)};
}

cmem_t mpc_ecdsa2p_key_get_x_share(mpc_ecdsa2pc_key_ref* key) {
  if (!valid_ref(key)) return cmem_t{nullptr, 0};
  const auto& k = *as<ecdsa2pc::key_t>(key->opaque);
  return copy_to_cmem(k.x_share.to_bin(x_share_bin_size(k.x_share, k.curve)));
}

int mpc_ecdsa2p_key_get_curve_code(mpc_ecdsa2pc_key_ref* key) {
  if (!valid_ref(key)) return -1;
  return as<ecdsa2pc::key_t>(key->opaque)->curve.get_openssl_code();
}

// Layout (unchanged from the cgobinding era): [role:int32, curve, Q, x_share, c_key, paillier].
int serialize_mpc_ecdsa2p(mpc_ecdsa2pc_key_ref* k, cmems_t* ser) {
  if (!valid_ref(k) || !ser) return E_BADARG;
  const auto& key = *as<ecdsa2pc::key_t>(k->opaque);
  int32_t role = static_cast<int32_t>(key.role);
  std::vector<buf_t> parts = {coinbase::ser(role),        coinbase::ser(key.curve), coinbase::ser(key.Q),
                              coinbase::ser(key.x_share), coinbase::ser(key.c_key), coinbase::ser(key.paillier)};
  *ser = copy_to_cmems(buf_t::to_mems(parts));
  return 0;
}

int deserialize_mpc_ecdsa2p(cmems_t sers, mpc_ecdsa2pc_key_ref* k) {
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
  *k = mpc_ecdsa2pc_key_ref{key.release()};
  return 0;
}

// ===========================================================================
// EC key 2P / Schnorr 2P
// ===========================================================================

int mpc_eckey_2p_dkg(job_2p_ref* j, int curve_code, mpc_eckey_2p_ref* k) {
  job_2p_t* job = job_of(j);
  ecurve_t curve = ecurve_t::find(curve_code);
  if (!job || !k || !curve) return E_BADARG;

  auto key = std::make_unique<eckey::key_share_2p_t>();
  buf_t sid;
  if (error_t rv = eckey::key_share_2p_t::dkg(*job, curve, *key, sid)) return rv;
  *k = mpc_eckey_2p_ref{key.release()};
  return 0;
}

int mpc_schnorr2p_eddsa_sign(job_2p_ref* j, mpc_eckey_2p_ref* k, cmem_t msg, cmem_t* sig_out) {
  job_2p_t* job = job_of(j);
  if (!job || !valid_ref(k) || !sig_out) return E_BADARG;
  *sig_out = cmem_t{nullptr, 0};

  buf_t sig;
  if (error_t rv = schnorr2p::sign(*job, *as<eckey::key_share_2p_t>(k->opaque), view(msg), sig,
                                   schnorr2p::variant_e::EdDSA))
    return rv;
  *sig_out = copy_to_cmem(sig);
  return 0;
}

void free_mpc_eckey_2p(mpc_eckey_2p_ref key) { delete as<eckey::key_share_2p_t>(key.opaque); }

int mpc_eckey_2p_get_role_index(mpc_eckey_2p_ref* key) {
  if (!valid_ref(key)) return -1;
  return static_cast<int>(as<eckey::key_share_2p_t>(key->opaque)->role);
}

ecc_point_ref mpc_eckey_2p_get_Q(mpc_eckey_2p_ref* key) {
  if (!valid_ref(key)) return ecc_point_ref{nullptr};
  return ecc_point_ref{new ecc_point_t(as<eckey::key_share_2p_t>(key->opaque)->Q)};
}

cmem_t mpc_eckey_2p_get_x_share(mpc_eckey_2p_ref* key) {
  if (!valid_ref(key)) return cmem_t{nullptr, 0};
  const auto& k = *as<eckey::key_share_2p_t>(key->opaque);
  return copy_to_cmem(k.x_share.to_bin(x_share_bin_size(k.x_share, k.curve)));
}

int mpc_eckey_2p_get_curve_code(mpc_eckey_2p_ref* key) {
  if (!valid_ref(key)) return -1;
  return as<eckey::key_share_2p_t>(key->opaque)->curve.get_openssl_code();
}

// Layout: [role:int32, curve, Q, x_share].
int serialize_mpc_eckey_2p(mpc_eckey_2p_ref* k, cmems_t* ser) {
  if (!valid_ref(k) || !ser) return E_BADARG;
  const auto& key = *as<eckey::key_share_2p_t>(k->opaque);
  int32_t role = static_cast<int32_t>(key.role);
  std::vector<buf_t> parts = {coinbase::ser(role), coinbase::ser(key.curve), coinbase::ser(key.Q),
                              coinbase::ser(key.x_share)};
  *ser = copy_to_cmems(buf_t::to_mems(parts));
  return 0;
}

int deserialize_mpc_eckey_2p(cmems_t sers, mpc_eckey_2p_ref* k) {
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
  *k = mpc_eckey_2p_ref{key.release()};
  return 0;
}

// ===========================================================================
// EC key MP, ECDSA MP, EdDSA MP
// ===========================================================================

int mpc_eckey_mp_dkg(job_mp_ref* j, ecurve_ref* curve, mpc_eckey_mp_ref* k) {
  job_mp_t* job = job_of(j);
  if (!job || !valid_ref(curve) || !k) return E_BADARG;

  auto key = std::make_unique<eckey::key_share_mp_t>();
  buf_t sid;
  if (error_t rv = eckey::key_share_mp_t::dkg(*job, *as<ecurve_t>(curve->opaque), *key, sid)) return rv;
  *k = mpc_eckey_mp_ref{key.release()};
  return 0;
}

int mpc_eckey_mp_refresh(job_mp_ref* j, cmem_t sid_mem, mpc_eckey_mp_ref* k, mpc_eckey_mp_ref* nk) {
  job_mp_t* job = job_of(j);
  if (!job || !valid_ref(k) || !nk) return E_BADARG;

  auto new_key = std::make_unique<eckey::key_share_mp_t>();
  buf_t sid(view(sid_mem));
  if (error_t rv = eckey::key_share_mp_t::refresh(*job, sid, *as<eckey::key_share_mp_t>(k->opaque), *new_key))
    return rv;
  *nk = mpc_eckey_mp_ref{new_key.release()};
  return 0;
}

void free_mpc_eckey_mp(mpc_eckey_mp_ref key) { delete as<eckey::key_share_mp_t>(key.opaque); }

int mpc_eckey_mp_get_party_name(mpc_eckey_mp_ref* k, cmem_t* party_name) {
  if (!valid_ref(k) || !party_name) return 1;
  *party_name = copy_to_cmem(mem_t(as<eckey::key_share_mp_t>(k->opaque)->party_name));
  return 0;
}

int mpc_eckey_mp_get_x_share(mpc_eckey_mp_ref* k, cmem_t* x_share) {
  if (!valid_ref(k) || !x_share) return 1;
  const auto& key = *as<eckey::key_share_mp_t>(k->opaque);
  *x_share = copy_to_cmem(key.x_share.to_bin(key.curve.order().get_bin_size()));
  return 0;
}

ecc_point_ref mpc_eckey_mp_get_Q(mpc_eckey_mp_ref* k) {
  if (!valid_ref(k)) return ecc_point_ref{nullptr};
  return ecc_point_ref{new ecc_point_t(as<eckey::key_share_mp_t>(k->opaque)->Q)};
}

ecurve_ref mpc_eckey_mp_get_curve(mpc_eckey_mp_ref* k) {
  if (!valid_ref(k)) return ecurve_ref{nullptr};
  return ecurve_ref{new ecurve_t(as<eckey::key_share_mp_t>(k->opaque)->curve)};
}

// Layout: [x_share, Q, Qis, curve, party_name].
int serialize_mpc_eckey_mp(mpc_eckey_mp_ref* k, cmems_t* ser) {
  if (!valid_ref(k) || !ser) return E_BADARG;
  const auto& key = *as<eckey::key_share_mp_t>(k->opaque);
  std::vector<buf_t> parts = {coinbase::ser(key.x_share), coinbase::ser(key.Q), coinbase::ser(key.Qis),
                              coinbase::ser(key.curve), coinbase::ser(key.party_name)};
  *ser = copy_to_cmems(buf_t::to_mems(parts));
  return 0;
}

int deserialize_mpc_eckey_mp(cmems_t sers, mpc_eckey_mp_ref* k) {
  if (!k) return E_BADARG;
  std::vector<buf_t> parts = bufs_from_cmems(sers);
  if (parts.size() != 5) return E_FORMAT;

  auto key = std::make_unique<eckey::key_share_mp_t>();
  if (coinbase::deser(parts[0], key->x_share)) return E_FORMAT;
  if (coinbase::deser(parts[1], key->Q)) return E_FORMAT;
  if (coinbase::deser(parts[2], key->Qis)) return E_FORMAT;
  if (coinbase::deser(parts[3], key->curve)) return E_FORMAT;
  if (coinbase::deser(parts[4], key->party_name)) return E_FORMAT;
  *k = mpc_eckey_mp_ref{key.release()};
  return 0;
}

int mpc_ecdsampc_sign(job_mp_ref* j, mpc_eckey_mp_ref* k, cmem_t msg, int sig_receiver, cmem_t* sig_out) {
  job_mp_t* job = job_of(j);
  if (!job || !valid_ref(k) || !sig_out) return E_BADARG;
  *sig_out = cmem_t{nullptr, 0};

  buf_t sig;
  if (error_t rv =
          ecdsampc::sign(*job, *as<ecdsampc::key_t>(k->opaque), view(msg), party_idx_t(sig_receiver), sig))
    return rv;
  *sig_out = copy_to_cmem(sig);
  return 0;
}

int mpc_eddsampc_sign(job_mp_ref* j, mpc_eckey_mp_ref* k, cmem_t msg, int sig_receiver, cmem_t* sig_out) {
  job_mp_t* job = job_of(j);
  if (!job || !valid_ref(k) || !sig_out) return E_BADARG;
  *sig_out = cmem_t{nullptr, 0};

  buf_t sig;
  if (error_t rv =
          eddsampc::sign(*job, *as<eddsampc::key_t>(k->opaque), view(msg), party_idx_t(sig_receiver), sig))
    return rv;
  *sig_out = copy_to_cmem(sig);
  return 0;
}

// ===========================================================================
// ZK and agree-random
// ===========================================================================

int zk_dl_prove(ecc_point_ref* Q, cmem_t w_mem, cmem_t sid_mem, uint64_t aux, cmem_t* proof_out) {
  if (!valid_ref(Q) || !proof_out) return E_BADARG;
  coinbase::zk::uc_dl_t zk;
  zk.prove(*as<ecc_point_t>(Q->opaque), bn_t::from_bin(view(w_mem)), view(sid_mem), aux);
  *proof_out = copy_to_cmem(coinbase::ser(zk));
  return 0;
}

int zk_dl_verify(ecc_point_ref* Q, cmem_t proof, cmem_t sid_mem, uint64_t aux) {
  if (!valid_ref(Q)) return E_BADARG;
  coinbase::zk::uc_dl_t zk;
  if (error_t rv = coinbase::deser(view(proof), zk)) return rv;
  return zk.verify(*as<ecc_point_t>(Q->opaque), view(sid_mem), aux);
}

int mpc_agree_random(job_2p_ref* j, int bit_len, cmem_t* out) {
  job_2p_t* job = job_of(j);
  if (!job || !out || bit_len <= 0) return NETWORK_PARAM_ERROR;
  buf_t out_buf;
  if (error_t rv = agree_random(*job, bit_len, out_buf)) return rv;
  *out = copy_to_cmem(out_buf);
  return 0;
}
