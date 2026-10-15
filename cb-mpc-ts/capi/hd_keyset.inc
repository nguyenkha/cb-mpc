// HD keysets for the cb-mpc-ts C ABI (see hd_keyset.h).
//
// Included at the end of cbmpc_ts.cpp so it shares that file's internal
// helpers (guard, copy_to_cmem_rv, validate_*); keep it free of upstream edits.

#include <cbmpc/internal/protocol/hd_keyset_ecdsa_2p.h>
#include <cbmpc/internal/protocol/hd_keyset_eddsa_2p.h>
#include <cbmpc/internal/protocol/hd_tree_bip32.h>
#include <cbmpc/internal/protocol/sid.h>

#include "hd_keyset.h"

namespace {

using hd_ecdsa_t = coinbase::mpc::key_share_ecdsa_hdmpc_2p_t;
using hd_eddsa_t = coinbase::mpc::key_share_eddsa_hdmpc_2p_t;

constexpr uint32_t kHardenedBit = 0x80000000u;
constexpr int kMaxPathDepth = 255;
constexpr int kMaxPathsPerCall = 1024;

// Big-endian uint32 array -> path. Rejects ragged buffers and absurd depths.
error_t parse_path(mem_t bytes, coinbase::mpc::bip32_path_t& out) {
  if (bytes.size < 0 || bytes.size % 4 != 0 || bytes.size / 4 > kMaxPathDepth) return E_BADARG;
  if (bytes.size > 0 && !bytes.data) return E_BADARG;
  out = coinbase::mpc::bip32_path_t();
  for (int i = 0; i < bytes.size; i += 4) out.append(coinbase::be_get_4(bytes.data + i));
  return SUCCESS;
}

// Non-hardened paths must use indices < 2^31 (BIP32 public derivation only).
error_t parse_non_hardened_paths(const cmems_t* in, int count, std::vector<coinbase::mpc::bip32_path_t>& out) {
  if (!in || in->count != count || count < 1 || count > kMaxPathsPerCall) return E_BADARG;
  if (cmems_total_size(*in) < 0) return E_BADARG;
  std::vector<buf_t> parts = bufs_from_cmems(*in);
  out.resize(parts.size());
  for (size_t i = 0; i < parts.size(); i++) {
    if (error_t rv = parse_path(parts[i], out[i])) return rv;
    for (uint32_t index : out[i].get())
      if (index & kHardenedBit) return E_BADARG;
  }
  if (coinbase::mpc::bip32_path_t::has_duplicate(out)) return E_BADARG;
  return SUCCESS;
}

// Signing-key view of an ECDSA keyset, for reuse of the ECDSA-2P key validation.
ecdsa2pc::key_t ecdsa_key_of(const hd_ecdsa_t& ks) {
  return ecdsa2pc::key_t{party_t(ks.party_index), ks.curve, ks.root.Q, ks.root.x_share, ks.c_key, ks.paillier};
}

eckey::key_share_2p_t eddsa_key_of(const hd_eddsa_t& ks) {
  return eckey::key_share_2p_t{party_t(ks.party_index), ks.curve, ks.root.Q, ks.root.x_share};
}

// VRF part of a keyset: k in [0, q), K on the keyset curve (mirrors upstream api blob_to_keyset).
error_t validate_vrf_part(const ecurve_t& curve, const coinbase::mpc::hd_root_t& root) {
  if (!curve.order().is_in_range(root.k_share)) return E_FORMAT;
  return check_point(curve, root.K);
}

error_t validate_hd_ecdsa(const hd_ecdsa_t& ks) {
  if (ks.party_index != 0 && ks.party_index != 1) return E_FORMAT;
  if (validate_ecdsa2p_key(ecdsa_key_of(ks))) return E_FORMAT;
  return validate_vrf_part(ks.curve, ks.root);
}

error_t validate_hd_eddsa(const hd_eddsa_t& ks) {
  if (ks.party_index != 0 && ks.party_index != 1) return E_FORMAT;
  if (ks.curve != coinbase::crypto::curve_ed25519) return E_FORMAT;
  if (validate_eckey_2p_key(eddsa_key_of(ks))) return E_FORMAT;
  return validate_vrf_part(ks.curve, ks.root);
}

// Runs the VRF key DKG for an existing signing key, after both parties confirm
// they hold shares of the same public key Q.
error_t vrf_dkg_for_key(job_2p_t& job, const ecurve_t& curve, const ecc_point_t& Q, party_t role,
                        coinbase::mpc::hd_root_t& root) {
  error_t rv = UNINITIALIZED_ERROR;
  if (party_t(job.get_party_idx()) != role) return E_BADARG;

  ecc_point_t q_from_p1 = job.is_p1() ? Q : ecc_point_t();
  if (rv = job.p1_to_p2(q_from_p1)) return rv;
  ecc_point_t q_from_p2 = job.is_p2() ? Q : ecc_point_t();
  if (rv = job.p2_to_p1(q_from_p2)) return rv;
  if (job.is_p2() && q_from_p1 != Q) return coinbase::error(E_CRYPTO, "hd upgrade: parties hold different keys");
  if (job.is_p1() && q_from_p2 != Q) return coinbase::error(E_CRYPTO, "hd upgrade: parties hold different keys");

  eckey::key_share_2p_t k_key;
  buf_t sid;
  if (rv = eckey::key_share_2p_t::dkg(job, curve, k_key, sid)) return rv;
  root.k_share = k_key.x_share;
  root.K = k_key.Q;
  return SUCCESS;
}

// Hardened step of upstream's derive_keys (hd_keyset_{ecdsa,eddsa}_2p.cpp),
// returning the account node instead of derived keys. The node depends only
// on Z = k*P, so it matches upstream's derivation exactly; scripts/hd.ts
// checks that against derive_keys so an upstream change cannot drift silently.
error_t account_node(job_2p_t& job, const ecurve_t& curve, const coinbase::mpc::hd_root_t& root,
                     const coinbase::mpc::bip32_path_t& hardened_path, buf_t& sid, ecc_point_t& out_Q,
                     buf_t& out_chain_code) {
  error_t rv = UNINITIALIZED_ERROR;
  if (sid.empty()) {
    if (rv = coinbase::mpc::generate_sid_fixed_mp(job, sid)) return rv;
  }
  const buf256_t node_sid = coinbase::crypto::sha256_t::hash(std::string("cb-mpc-ts-hd-account-node-2p"),
                                                             uint64_t(sid.size()), sid, hardened_path);

  const auto& G = curve.generator();
  const mod_t& q = curve.order();
  const ecc_point_t K_share = root.get_K_share();
  const ecc_point_t other_K_share = root.get_other_K_share();

  const ecc_point_t P = coinbase::crypto::ro::hash_curve(hardened_path.get()).curve(curve);
  const ecc_point_t Z_share = root.k_share * P;
  ecc_point_t Z1, Z2;
  if (job.is_p1())
    Z1 = Z_share;
  else
    Z2 = Z_share;

  coinbase::zk::dh_t zk_dh1, zk_dh2;
  if (job.is_p1()) zk_dh1.prove(P, K_share, Z1, root.k_share, node_sid, 1);
  if (rv = job.p1_to_p2(Z1, zk_dh1)) return rv;
  if (job.is_p2()) {
    if (rv = zk_dh1.verify(P, other_K_share, Z1, node_sid, 1)) return rv;
    zk_dh2.prove(P, K_share, Z2, root.k_share, node_sid, 2);
  }
  if (rv = job.p2_to_p1(Z2, zk_dh2)) return rv;
  if (job.is_p1()) {
    if (rv = zk_dh2.verify(P, other_K_share, Z2, node_sid, 2)) return rv;
  }

  const ecc_point_t Z = Z1 + Z2;
  const int delta_size = curve.size() + 16;
  buf_t y = coinbase::crypto::ro::hash_string(Z).bitlen(bytes_to_bits(delta_size) + 256);
  const bn_t delta = bn_t::from_bin(y.take(delta_size)) % q;
  out_chain_code = y.skip(delta_size);
  out_Q = root.Q + delta * G;
  return SUCCESS;
}

template <typename KS>
int account_node_c(job_2p_ref* j, KS* ks, cmem_t* hardened_path, cmem_t* sid_in, cmem_t* out_public_key,
                   cmem_t* out_chain_code) {
  job_2p_t* job = job_of(j);
  if (!job || !ks || !hardened_path || !out_public_key || !out_chain_code) return E_BADARG;
  if (party_t(job->get_party_idx()) != party_t(ks->party_index)) return E_BADARG;
  coinbase::mpc::bip32_path_t hp;
  if (error_t rv = parse_path(view(*hardened_path), hp)) return rv;
  buf_t sid = sid_in ? buf_t(view(*sid_in)) : buf_t();

  ecc_point_t Q;
  buf_t chain_code;
  if (error_t rv = account_node(*job, ks->curve, ks->root, hp, sid, Q, chain_code)) return rv;
  if (int r = copy_to_cmem_rv(Q.to_compressed_bin(), out_public_key)) return r;
  if (int r = copy_to_cmem_rv(chain_code, out_chain_code)) {
    std::free(out_public_key->data);
    *out_public_key = cmem_t{nullptr, 0};
    return r;
  }
  return 0;
}

// Shared derive for both key types: KEY is the derived key type, REF its C handle.
template <typename KS, typename KEY, typename REF>
int derive_c(job_2p_ref* j, KS* ks, cmem_t* hardened_path, cmems_t* non_hardened_paths, cmem_t* sid_in,
             REF* out_keys, int count) {
  job_2p_t* job = job_of(j);
  if (!job || !ks || !hardened_path || !out_keys || count < 1) return E_BADARG;
  if (party_t(job->get_party_idx()) != party_t(ks->party_index)) return E_BADARG;
  coinbase::mpc::bip32_path_t hp;
  if (error_t rv = parse_path(view(*hardened_path), hp)) return rv;
  std::vector<coinbase::mpc::bip32_path_t> paths;
  if (error_t rv = parse_non_hardened_paths(non_hardened_paths, count, paths)) return rv;
  buf_t sid = sid_in ? buf_t(view(*sid_in)) : buf_t();

  std::vector<KEY> keys;
  if (error_t rv = KS::derive_keys(*job, *ks, hp, paths, sid, keys)) return rv;
  if (static_cast<int>(keys.size()) != count) return E_GENERAL;
  // Build every handle first so an allocation failure leaks no key material.
  std::vector<std::unique_ptr<KEY>> owned;
  owned.reserve(count);
  for (int i = 0; i < count; i++) owned.push_back(std::make_unique<KEY>(std::move(keys[i])));
  for (int i = 0; i < count; i++) out_keys[i] = REF{owned[i].release()};
  return 0;
}

}  // namespace

// ===========================================================================
// ECDSA-2P keysets
// ===========================================================================

int mpc_hd_ecdsa2p_dkg(job_2p_ref* j, int curve_code, mpc_hd_ecdsa2p_ref* out) {
  if (out) *out = mpc_hd_ecdsa2p_ref{nullptr};
  return guard_rv([&]() -> int {
    job_2p_t* job = job_of(j);
    ecurve_t curve = ecurve_t::find(curve_code);
    if (!job || !out || !curve || curve == coinbase::crypto::curve_ed25519) return E_BADARG;
    auto ks = std::make_unique<hd_ecdsa_t>();
    if (error_t rv = hd_ecdsa_t::dkg(*job, curve, *ks)) return rv;
    *out = mpc_hd_ecdsa2p_ref{ks.release()};
    return 0;
  });
}

int mpc_hd_ecdsa2p_from_key(job_2p_ref* j, mpc_ecdsa2pc_key_ref* k, mpc_hd_ecdsa2p_ref* out) {
  if (out) *out = mpc_hd_ecdsa2p_ref{nullptr};
  return guard_rv([&]() -> int {
    job_2p_t* job = job_of(j);
    if (!job || !valid_ref(k) || !out) return E_BADARG;
    const auto& key = *as<ecdsa2pc::key_t>(k->opaque);
    auto ks = std::make_unique<hd_ecdsa_t>();
    ks->curve = key.curve;
    ks->party_index = static_cast<party_idx_t>(key.role);
    ks->root.x_share = key.x_share;
    ks->root.Q = key.Q;
    ks->c_key = key.c_key;
    ks->paillier = key.paillier;
    if (error_t rv = vrf_dkg_for_key(*job, key.curve, key.Q, key.role, ks->root)) return rv;
    *out = mpc_hd_ecdsa2p_ref{ks.release()};
    return 0;
  });
}

int mpc_hd_ecdsa2p_refresh(job_2p_ref* j, mpc_hd_ecdsa2p_ref* ks, mpc_hd_ecdsa2p_ref* out) {
  if (out) *out = mpc_hd_ecdsa2p_ref{nullptr};
  return guard_rv([&]() -> int {
    job_2p_t* job = job_of(j);
    if (!job || !valid_ref(ks) || !out) return E_BADARG;
    auto& cur = *as<hd_ecdsa_t>(ks->opaque);
    if (party_t(job->get_party_idx()) != party_t(cur.party_index)) return E_BADARG;
    auto next = std::make_unique<hd_ecdsa_t>();
    if (error_t rv = hd_ecdsa_t::refresh(*job, cur, *next)) return rv;
    *out = mpc_hd_ecdsa2p_ref{next.release()};
    return 0;
  });
}

int mpc_hd_ecdsa2p_derive(job_2p_ref* j, mpc_hd_ecdsa2p_ref* ks, cmem_t* hardened_path, cmems_t* non_hardened_paths,
                          cmem_t* sid, mpc_ecdsa2pc_key_ref* out_keys, int count) {
  if (out_keys && count > 0)
    for (int i = 0; i < count; i++) out_keys[i] = mpc_ecdsa2pc_key_ref{nullptr};
  return guard_rv([&]() -> int {
    if (!valid_ref(ks)) return E_BADARG;
    return derive_c<hd_ecdsa_t, ecdsa2pc::key_t>(j, as<hd_ecdsa_t>(ks->opaque), hardened_path, non_hardened_paths,
                                                 sid, out_keys, count);
  });
}

int mpc_hd_ecdsa2p_account_node(job_2p_ref* j, mpc_hd_ecdsa2p_ref* ks, cmem_t* hardened_path, cmem_t* sid,
                                cmem_t* out_public_key, cmem_t* out_chain_code) {
  if (out_public_key) *out_public_key = cmem_t{nullptr, 0};
  if (out_chain_code) *out_chain_code = cmem_t{nullptr, 0};
  return guard_rv([&]() -> int {
    if (!valid_ref(ks)) return E_BADARG;
    return account_node_c(j, as<hd_ecdsa_t>(ks->opaque), hardened_path, sid, out_public_key, out_chain_code);
  });
}

int mpc_hd_ecdsa2p_get_Q(mpc_hd_ecdsa2p_ref* ks, ecc_point_ref* out) {
  if (out) *out = ecc_point_ref{nullptr};
  return guard_rv([&]() -> int {
    if (!valid_ref(ks) || !out) return E_BADARG;
    *out = ecc_point_ref{new ecc_point_t(as<hd_ecdsa_t>(ks->opaque)->root.Q)};
    return 0;
  });
}

int mpc_hd_ecdsa2p_get_role_index(mpc_hd_ecdsa2p_ref* ks) {
  if (!valid_ref(ks)) return -1;
  return static_cast<int>(as<hd_ecdsa_t>(ks->opaque)->party_index);
}

int mpc_hd_ecdsa2p_get_curve_code(mpc_hd_ecdsa2p_ref* ks) {
  if (!valid_ref(ks)) return -1;
  return guard<int>(-1, [&]() -> int { return as<hd_ecdsa_t>(ks->opaque)->curve.get_openssl_code(); });
}

// Layout: [role:int32, curve, Q, x_share, c_key, paillier, K, k_share].
int serialize_mpc_hd_ecdsa2p(mpc_hd_ecdsa2p_ref* ks, cmems_t* ser) {
  if (ser) *ser = cmems_t{0, nullptr, nullptr};
  return guard_rv([&]() -> int {
    if (!valid_ref(ks) || !ser) return E_BADARG;
    const auto& k = *as<hd_ecdsa_t>(ks->opaque);
    int32_t role = static_cast<int32_t>(k.party_index);
    std::vector<buf_t> parts = {coinbase::ser(role),        coinbase::ser(k.curve),        coinbase::ser(k.root.Q),
                                coinbase::ser(k.root.x_share), coinbase::ser(k.c_key),     coinbase::ser(k.paillier),
                                coinbase::ser(k.root.K),    coinbase::ser(k.root.k_share)};
    return copy_to_cmems_rv(buf_t::to_mems(parts), ser);
  });
}

int deserialize_mpc_hd_ecdsa2p(cmems_t* ser, mpc_hd_ecdsa2p_ref* out) {
  if (out) *out = mpc_hd_ecdsa2p_ref{nullptr};
  return guard_rv([&]() -> int {
    if (!ser || !out || cmems_total_size(*ser) < 0) return E_BADARG;
    std::vector<buf_t> parts = bufs_from_cmems(*ser);
    if (parts.size() != 8) return E_FORMAT;
    auto ks = std::make_unique<hd_ecdsa_t>();
    int32_t role;
    if (coinbase::deser(parts[0], role) || (role != 0 && role != 1)) return E_FORMAT;
    ks->party_index = role;
    if (coinbase::deser(parts[1], ks->curve)) return E_FORMAT;
    if (coinbase::deser(parts[2], ks->root.Q)) return E_FORMAT;
    if (coinbase::deser(parts[3], ks->root.x_share)) return E_FORMAT;
    if (coinbase::deser(parts[4], ks->c_key)) return E_FORMAT;
    if (coinbase::deser(parts[5], ks->paillier)) return E_FORMAT;
    if (coinbase::deser(parts[6], ks->root.K)) return E_FORMAT;
    if (coinbase::deser(parts[7], ks->root.k_share)) return E_FORMAT;
    if (validate_hd_ecdsa(*ks)) return E_FORMAT;
    *out = mpc_hd_ecdsa2p_ref{ks.release()};
    return 0;
  });
}

void free_mpc_hd_ecdsa2p(mpc_hd_ecdsa2p_ref* ks) {
  if (ks) delete as<hd_ecdsa_t>(ks->opaque);
}

// ===========================================================================
// EdDSA-2P keysets
// ===========================================================================

int mpc_hd_eddsa2p_dkg(job_2p_ref* j, int curve_code, mpc_hd_eddsa2p_ref* out) {
  if (out) *out = mpc_hd_eddsa2p_ref{nullptr};
  return guard_rv([&]() -> int {
    job_2p_t* job = job_of(j);
    ecurve_t curve = ecurve_t::find(curve_code);
    if (!job || !out || curve != coinbase::crypto::curve_ed25519) return E_BADARG;
    auto ks = std::make_unique<hd_eddsa_t>();
    if (error_t rv = hd_eddsa_t::dkg(*job, curve, *ks)) return rv;
    *out = mpc_hd_eddsa2p_ref{ks.release()};
    return 0;
  });
}

int mpc_hd_eddsa2p_from_key(job_2p_ref* j, mpc_eckey_2p_ref* k, mpc_hd_eddsa2p_ref* out) {
  if (out) *out = mpc_hd_eddsa2p_ref{nullptr};
  return guard_rv([&]() -> int {
    job_2p_t* job = job_of(j);
    if (!job || !valid_ref(k) || !out) return E_BADARG;
    const auto& key = *as<eckey::key_share_2p_t>(k->opaque);
    if (key.curve != coinbase::crypto::curve_ed25519) return E_BADARG;
    auto ks = std::make_unique<hd_eddsa_t>();
    ks->curve = key.curve;
    ks->party_index = static_cast<party_idx_t>(key.role);
    ks->root.x_share = key.x_share;
    ks->root.Q = key.Q;
    if (error_t rv = vrf_dkg_for_key(*job, key.curve, key.Q, key.role, ks->root)) return rv;
    *out = mpc_hd_eddsa2p_ref{ks.release()};
    return 0;
  });
}

int mpc_hd_eddsa2p_refresh(job_2p_ref* j, mpc_hd_eddsa2p_ref* ks, mpc_hd_eddsa2p_ref* out) {
  if (out) *out = mpc_hd_eddsa2p_ref{nullptr};
  return guard_rv([&]() -> int {
    job_2p_t* job = job_of(j);
    if (!job || !valid_ref(ks) || !out) return E_BADARG;
    auto& cur = *as<hd_eddsa_t>(ks->opaque);
    if (party_t(job->get_party_idx()) != party_t(cur.party_index)) return E_BADARG;
    auto next = std::make_unique<hd_eddsa_t>();
    if (error_t rv = hd_eddsa_t::refresh(*job, cur, *next)) return rv;
    *out = mpc_hd_eddsa2p_ref{next.release()};
    return 0;
  });
}

int mpc_hd_eddsa2p_derive(job_2p_ref* j, mpc_hd_eddsa2p_ref* ks, cmem_t* hardened_path, cmems_t* non_hardened_paths,
                          cmem_t* sid, mpc_eckey_2p_ref* out_keys, int count) {
  if (out_keys && count > 0)
    for (int i = 0; i < count; i++) out_keys[i] = mpc_eckey_2p_ref{nullptr};
  return guard_rv([&]() -> int {
    if (!valid_ref(ks)) return E_BADARG;
    return derive_c<hd_eddsa_t, eckey::key_share_2p_t>(j, as<hd_eddsa_t>(ks->opaque), hardened_path,
                                                        non_hardened_paths, sid, out_keys, count);
  });
}

int mpc_hd_eddsa2p_account_node(job_2p_ref* j, mpc_hd_eddsa2p_ref* ks, cmem_t* hardened_path, cmem_t* sid,
                                cmem_t* out_public_key, cmem_t* out_chain_code) {
  if (out_public_key) *out_public_key = cmem_t{nullptr, 0};
  if (out_chain_code) *out_chain_code = cmem_t{nullptr, 0};
  return guard_rv([&]() -> int {
    if (!valid_ref(ks)) return E_BADARG;
    return account_node_c(j, as<hd_eddsa_t>(ks->opaque), hardened_path, sid, out_public_key, out_chain_code);
  });
}

int mpc_hd_eddsa2p_get_Q(mpc_hd_eddsa2p_ref* ks, ecc_point_ref* out) {
  if (out) *out = ecc_point_ref{nullptr};
  return guard_rv([&]() -> int {
    if (!valid_ref(ks) || !out) return E_BADARG;
    *out = ecc_point_ref{new ecc_point_t(as<hd_eddsa_t>(ks->opaque)->root.Q)};
    return 0;
  });
}

int mpc_hd_eddsa2p_get_role_index(mpc_hd_eddsa2p_ref* ks) {
  if (!valid_ref(ks)) return -1;
  return static_cast<int>(as<hd_eddsa_t>(ks->opaque)->party_index);
}

int mpc_hd_eddsa2p_get_curve_code(mpc_hd_eddsa2p_ref* ks) {
  if (!valid_ref(ks)) return -1;
  return guard<int>(-1, [&]() -> int { return as<hd_eddsa_t>(ks->opaque)->curve.get_openssl_code(); });
}

// Layout: [role:int32, curve, Q, x_share, K, k_share].
int serialize_mpc_hd_eddsa2p(mpc_hd_eddsa2p_ref* ks, cmems_t* ser) {
  if (ser) *ser = cmems_t{0, nullptr, nullptr};
  return guard_rv([&]() -> int {
    if (!valid_ref(ks) || !ser) return E_BADARG;
    const auto& k = *as<hd_eddsa_t>(ks->opaque);
    int32_t role = static_cast<int32_t>(k.party_index);
    std::vector<buf_t> parts = {coinbase::ser(role),           coinbase::ser(k.curve),  coinbase::ser(k.root.Q),
                                coinbase::ser(k.root.x_share), coinbase::ser(k.root.K), coinbase::ser(k.root.k_share)};
    return copy_to_cmems_rv(buf_t::to_mems(parts), ser);
  });
}

int deserialize_mpc_hd_eddsa2p(cmems_t* ser, mpc_hd_eddsa2p_ref* out) {
  if (out) *out = mpc_hd_eddsa2p_ref{nullptr};
  return guard_rv([&]() -> int {
    if (!ser || !out || cmems_total_size(*ser) < 0) return E_BADARG;
    std::vector<buf_t> parts = bufs_from_cmems(*ser);
    if (parts.size() != 6) return E_FORMAT;
    auto ks = std::make_unique<hd_eddsa_t>();
    int32_t role;
    if (coinbase::deser(parts[0], role) || (role != 0 && role != 1)) return E_FORMAT;
    ks->party_index = role;
    if (coinbase::deser(parts[1], ks->curve)) return E_FORMAT;
    if (coinbase::deser(parts[2], ks->root.Q)) return E_FORMAT;
    if (coinbase::deser(parts[3], ks->root.x_share)) return E_FORMAT;
    if (coinbase::deser(parts[4], ks->root.K)) return E_FORMAT;
    if (coinbase::deser(parts[5], ks->root.k_share)) return E_FORMAT;
    if (validate_hd_eddsa(*ks)) return E_FORMAT;
    *out = mpc_hd_eddsa2p_ref{ks.release()};
    return 0;
  });
}

void free_mpc_hd_eddsa2p(mpc_hd_eddsa2p_ref* ks) {
  if (ks) delete as<hd_eddsa_t>(ks->opaque);
}
