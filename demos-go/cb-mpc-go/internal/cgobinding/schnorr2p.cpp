#include "schnorr2p.h"

#include <memory>

#include <cbmpc/core/buf.h>
#include <cbmpc/crypto/base.h>
#include <cbmpc/protocol/ec_dkg.h>
#include <cbmpc/protocol/schnorr_2p.h>
#include <cbmpc/protocol/mpc_job_session.h>
#include <cbmpc/ffi/cmem_adapter.h>

#include "curve.h"
#include "network.h"

using namespace coinbase;
using namespace coinbase::mpc;

int mpc_eckey_2p_dkg(job_2p_ref* j, int curve_code, mpc_eckey_2p_ref* k) {
  job_2p_t* job = static_cast<job_2p_t*>(j->opaque);
  ecurve_t curve = ecurve_t::find(curve_code);

  eckey::key_share_2p_t* key = new eckey::key_share_2p_t();
  buf_t sid;

  error_t err = eckey::key_share_2p_t::dkg(*job, curve, *key, sid);
  if (err) {
    delete key;
    return err;
  }
  *k = mpc_eckey_2p_ref{key};

  return 0;
}

int mpc_schnorr2p_eddsa_sign(job_2p_ref* j, mpc_eckey_2p_ref* k, cmem_t msg_mem, cmem_t* sig_out) {
  job_2p_t* job = static_cast<job_2p_t*>(j->opaque);
  eckey::key_share_2p_t* key = static_cast<eckey::key_share_2p_t*>(k->opaque);

  mem_t msg(msg_mem.data, msg_mem.size);
  buf_t sig;

  error_t err = schnorr2p::sign(*job, *key, msg, sig, schnorr2p::variant_e::EdDSA);
  if (err) return err;

  *sig_out = coinbase::ffi::copy_to_cmem(sig);
  return 0;
}

// ============ Memory Management =================
void free_mpc_eckey_2p(mpc_eckey_2p_ref ctx) {
  if (ctx.opaque) {
    delete static_cast<eckey::key_share_2p_t*>(ctx.opaque);
  }
}

// ============ Accessors =========================

int mpc_eckey_2p_get_role_index(mpc_eckey_2p_ref* key) {
  if (key == NULL || key->opaque == NULL) {
    return -1;
  }
  eckey::key_share_2p_t* k = static_cast<eckey::key_share_2p_t*>(key->opaque);
  return static_cast<int>(k->role);
}

ecc_point_ref mpc_eckey_2p_get_Q(mpc_eckey_2p_ref* key) {
  if (key == NULL || key->opaque == NULL) {
    return ecc_point_ref{nullptr};
  }
  eckey::key_share_2p_t* k = static_cast<eckey::key_share_2p_t*>(key->opaque);
  ecc_point_t* Q_copy = new ecc_point_t(k->Q);
  return ecc_point_ref{Q_copy};
}

cmem_t mpc_eckey_2p_get_x_share(mpc_eckey_2p_ref* key) {
  if (key == NULL || key->opaque == NULL) {
    return cmem_t{nullptr, 0};
  }
  eckey::key_share_2p_t* k = static_cast<eckey::key_share_2p_t*>(key->opaque);
  int bin_size = std::max(k->x_share.get_bin_size(), k->curve.order().get_bin_size());
  buf_t x_buf = k->x_share.to_bin(bin_size);
  return coinbase::ffi::copy_to_cmem(x_buf);
}

int mpc_eckey_2p_get_curve_code(mpc_eckey_2p_ref* key) {
  if (key == NULL || key->opaque == NULL) {
    return -1;
  }
  eckey::key_share_2p_t* k = static_cast<eckey::key_share_2p_t*>(key->opaque);
  return k->curve.get_openssl_code();
}

// ============ Serialization =====================

int serialize_mpc_eckey_2p(mpc_eckey_2p_ref* k, cmems_t* ser) {
  eckey::key_share_2p_t* key = static_cast<eckey::key_share_2p_t*>(k->opaque);

  int32_t role_val = static_cast<int32_t>(key->role);
  auto role = coinbase::ser(role_val);
  auto curve = coinbase::ser(key->curve);
  auto Q = coinbase::ser(key->Q);
  auto x_share = coinbase::ser(key->x_share);

  auto out = std::vector<mem_t>{role, curve, Q, x_share};
  *ser = coinbase::ffi::copy_to_cmems(out);
  return 0;
}

int deserialize_mpc_eckey_2p(cmems_t sers, mpc_eckey_2p_ref* k) {
  std::unique_ptr<eckey::key_share_2p_t> key(new eckey::key_share_2p_t());
  std::vector<buf_t> sers_vec = coinbase::ffi::bufs_from_cmems(sers);

  int32_t role_val;
  if (coinbase::deser(sers_vec[0], role_val)) return 1;
  key->role = static_cast<party_t>(role_val);
  if (coinbase::deser(sers_vec[1], key->curve)) return 1;
  if (coinbase::deser(sers_vec[2], key->Q)) return 1;
  if (coinbase::deser(sers_vec[3], key->x_share)) return 1;

  *k = mpc_eckey_2p_ref{key.release()};
  return 0;
}
