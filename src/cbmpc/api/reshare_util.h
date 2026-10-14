#pragma once

// Fork addition: shared argument handling for `{ecdsa,eddsa}_mp::reshare_from_additive` and
// `{ecdsa,eddsa}_mp::ac_key_to_additive_share`.

#include <set>
#include <string>
#include <string_view>
#include <vector>

#include <cbmpc/core/access_structure.h>
#include <cbmpc/core/error.h>
#include <cbmpc/core/job.h>
#include <cbmpc/internal/protocol/ec_dkg.h>

#include "access_structure_util.h"
#include "job_util.h"
#include "mem_util.h"

namespace coinbase::api::detail {

// Upper bound for an additive-share encoding. ECDSA-2P P1 shares are Paillier-plaintext integers that can exceed q
// after refreshes (each refresh adds < q), so they are accepted unreduced and reduced mod q here.
inline constexpr int MAX_ADDITIVE_SHARE_SIZE = 64;

// Validates the public arguments, runs the internal reshare protocol and returns the new key (when this party is in
// the new access structure) plus the new party names, ordered as in `job.party_names` and pointing into it.
inline error_t run_reshare_from_additive(const job_mp_t& job, const coinbase::crypto::ecurve_t& curve, buf_t& sid,
                                         mem_t public_key_compressed,
                                         const std::vector<std::string_view>& dealer_party_names, mem_t additive_share,
                                         const access_structure_t& new_access_structure,
                                         std::vector<std::string_view>& out_new_party_names,
                                         coinbase::mpc::eckey::key_share_mp_t& new_key, bool& has_new_key) {
  has_new_key = false;
  out_new_party_names.clear();
  error_t rv = validate_job_mp(job);
  if (rv) return rv;
  if (rv = validate_mem_arg(public_key_compressed, "public_key_compressed")) return rv;

  coinbase::crypto::ecc_point_t Q;
  if (rv = Q.from_bin(curve, public_key_compressed)) return coinbase::error(rv, "invalid public_key_compressed");

  // The new structure's leaves must be job parties; build it over exactly those leaves.
  std::set<std::string> leaf_names;
  if (rv = validate_access_structure_node(new_access_structure)) return rv;
  if (rv = collect_leaf_names(new_access_structure, leaf_names)) return rv;
  for (const auto& name : job.party_names) {
    if (leaf_names.count(std::string(name))) out_new_party_names.push_back(name);
  }
  if (out_new_party_names.size() != leaf_names.size())
    return coinbase::error(E_BADARG, "new access structure party is not in job.party_names");

  coinbase::crypto::ss::ac_owned_t ac;
  if (rv = to_internal_access_structure(new_access_structure, out_new_party_names, curve, ac)) return rv;

  coinbase::mpc::party_set_t dealer_party_set;
  if (rv = to_internal_party_set(job.party_names, dealer_party_names, dealer_party_set)) return rv;

  const bool is_dealer = dealer_party_set.has(job.self);
  coinbase::crypto::bn_t x;
  if (is_dealer) {
    if (rv = validate_mem_arg_max_size(additive_share, "additive_share", MAX_ADDITIVE_SHARE_SIZE)) return rv;
    if (additive_share.size == 0) return coinbase::error(E_BADARG, "dealer must provide additive_share");
    x = coinbase::crypto::bn_t::from_bin(additive_share) % curve.order();
    if (x == 0) return coinbase::error(E_BADARG, "zero additive share");
  } else if (additive_share.size != 0) {
    return coinbase::error(E_BADARG, "additive_share given by a party that is not a dealer");
  }

  coinbase::mpc::job_mp_t mpc_job = to_internal_job(job);
  return coinbase::mpc::eckey::key_share_mp_t::reshare_ac(mpc_job, curve, sid, ac, dealer_party_set, Q, x, new_key,
                                                          has_new_key);
}

// Converts this party's access-structure share into its additive share for `quorum_party_names`
// (Lagrange-weighted). The additive shares of exactly that quorum sum to the private key.
inline error_t ac_key_to_additive_scalar(coinbase::mpc::eckey::key_share_mp_t& ac_key,
                                         const access_structure_t& access_structure,
                                         const std::vector<std::string_view>& quorum_party_names,
                                         buf_t& out_additive_share_fixed) {
  out_additive_share_fixed.free();
  std::vector<std::string_view> all_party_names;
  all_party_names.reserve(ac_key.Qis.size());
  for (const auto& kv : ac_key.Qis) all_party_names.emplace_back(kv.first);

  coinbase::mpc::party_set_t quorum_party_set;
  error_t rv = to_internal_party_set(all_party_names, quorum_party_names, quorum_party_set);
  if (rv) return rv;
  bool self_in_quorum = false;
  for (const auto& name : quorum_party_names) self_in_quorum |= (name == ac_key.party_name);
  if (!self_in_quorum) return coinbase::error(E_BADARG, "key owner is not in quorum_party_names");

  coinbase::crypto::ss::ac_owned_t ac;
  if (rv = to_internal_access_structure(access_structure, all_party_names, ac_key.curve, ac)) return rv;

  std::set<coinbase::crypto::pname_t> quorum_names;
  for (const auto& name : quorum_party_names) quorum_names.insert(std::string(name));

  coinbase::mpc::eckey::key_share_mp_t additive_key;
  if (rv = ac_key.to_additive_share(ac, quorum_names, additive_key)) return rv;
  // A member beyond the selected qualifying subset (e.g. the third party of a 2-of-3 quorum of three) gets weight 0;
  // dealing 0 would abort the reshare with an opaque error, so reject it here.
  if (additive_key.x_share == 0)
    return coinbase::error(E_BADARG, "quorum member has zero weight; pass a minimal qualifying set");
  out_additive_share_fixed = additive_key.x_share.to_bin(ac_key.curve.order().get_bin_size());
  return SUCCESS;
}

}  // namespace coinbase::api::detail
