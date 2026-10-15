// Fork addition: reshare an existing EC key (known public key Q) from a qualifying set of additive-share holders
// ("dealers") to a new access structure, keeping Q. Follows the message flow of `dkg_or_refresh_ac` in ec_dkg.cpp:
// each dealer shares its additive share with `share_with_internals`, commits to all public node shares (Feldman-style
// commitments over the AC tree), proves knowledge of their discrete logs, and sends each new party its share. The
// difference from DKG/refresh is the dealt secret (the dealer's additive share instead of random / zero) and the extra
// check that the dealt roots sum to the expected Q.
#include <cbmpc/internal/crypto/ro.h>
#include <cbmpc/internal/protocol/ec_dkg.h>
#include <cbmpc/internal/protocol/sid.h>
#include <cbmpc/internal/protocol/util.h>

using namespace coinbase::crypto::ss;

#define _i msg
#define _j received(j)

namespace coinbase::mpc::eckey {

namespace {

// Canonical, unambiguous encoding of the access-structure tree, so every party hashes the same structure.
// Children are walked in insertion order on purpose: the additive-share conversion also depends on it, so parties
// that built the "same" tree in a different child order must not agree.
void encode_ac_node(const node_t* node, std::string& out) {
  out += std::to_string(int(node->type)) + ":" + std::to_string(node->threshold) + ":" +
         std::to_string(node->name.size()) + ":" + node->name + ":" + std::to_string(node->get_n()) + ";";
  for (const node_t* child : node->children) encode_ac_node(child, out);
}

void collect_node_names(const node_t* node, std::set<crypto::pname_t>& out) {
  out.insert(node->name);
  for (const node_t* child : node->children) collect_node_names(child, out);
}

}  // namespace

// Checks that a dealer's public node shares are one consistent sharing over the whole tree (every AND node is the
// sum of its children, every OR child equals its parent, every THRESHOLD node's children lie on one polynomial
// through it). `verify_share_against_ancestors_pub_data` only checks the receiver's own leaf-to-root path, which for
// OR / AND trees leaves other parties' public shares unchecked. Node names must already be present in `pub`.
error_t verify_ac_pub_tree(const node_t* node, const ac_internal_pub_shares_t& pub) {
  if (node->type == node_e::LEAF) return SUCCESS;
  crypto::vartime_scope_t vartime_scope;
  const ecc_point_t& P = pub.at(node->name);
  const std::vector<node_t*> children = node->get_sorted_children();
  if (node->type == node_e::AND) {
    ecc_point_t sum = P.get_curve().infinity();
    for (const node_t* c : children) sum += pub.at(c->name);
    if (sum != P) return coinbase::error(E_CRYPTO, "reshare: inconsistent AND node");
  } else if (node->type == node_e::OR) {
    for (const node_t* c : children) {
      if (pub.at(c->name) != P) return coinbase::error(E_CRYPTO, "reshare: inconsistent OR node");
    }
  } else if (node->type == node_e::THRESHOLD) {
    const int t = node->threshold;
    if (t < 1 || t > int(children.size())) return coinbase::error(E_CRYPTO, "reshare: invalid threshold node");
    std::vector<ecc_point_t> quorum;
    std::vector<bn_t> pids;
    for (int k = 0; k < t; k++) {
      quorum.push_back(pub.at(children[k]->name));
      pids.push_back(children[k]->get_pid());
    }
    if (crypto::lagrange_interpolate_exponent(0, quorum, pids) != P)
      return coinbase::error(E_CRYPTO, "reshare: inconsistent THRESHOLD node");
    for (size_t k = t; k < children.size(); k++) {
      if (crypto::lagrange_interpolate_exponent(children[k]->get_pid(), quorum, pids) != pub.at(children[k]->name))
        return coinbase::error(E_CRYPTO, "reshare: inconsistent THRESHOLD node");
    }
  } else {
    return coinbase::error(E_CRYPTO, "reshare: invalid node type");
  }
  for (const node_t* c : children) {
    if (error_t rv = verify_ac_pub_tree(c, pub)) return rv;
  }
  return SUCCESS;
}

error_t key_share_mp_t::reshare_ac(job_mp_t& job, const ecurve_t& curve, buf_t& sid, const crypto::ss::ac_t new_ac,
                                   const party_set_t& dealer_party_set, const ecc_point_t& Q,
                                   const bn_t& additive_share, key_share_mp_t& new_key, bool& has_new_key) {
  error_t rv = UNINITIALIZED_ERROR;
  has_new_key = false;

  const auto& G = curve.generator();
  const mod_t& q = curve.order();

  if (rv = new_ac.validate_tree()) return coinbase::error(rv, "reshare: invalid access structure");
  if (new_ac.get_curve() != curve) return coinbase::error(E_BADARG, "reshare: access structure curve mismatch");
  if (rv = curve.check(Q)) return coinbase::error(rv, "reshare: Q is not on the curve");
  if (Q.is_infinity()) return coinbase::error(E_BADARG, "reshare: Q is infinity");

  const int n = job.get_n_parties();
  const int i = job.get_party_idx();

  // Every leaf of the new structure must be an online party; parties outside it may only deal.
  const std::set<crypto::pname_t> leaf_names = new_ac.list_leaf_names();
  std::set<crypto::pname_t> job_names;
  for (int j = 0; j < n; j++) job_names.insert(job.get_name(j));
  for (const auto& name : leaf_names) {
    if (job_names.find(name) == job_names.end())
      return coinbase::error(E_BADARG, "reshare: new access structure party is not in the job");
  }

  std::vector<crypto::mpc_pid_t> all_pids(n);
  std::map<party_idx_t, crypto::mpc_pid_t> dealer_pids;
  for (int j = 0; j < n; j++) {
    all_pids[j] = job.get_pid(j);
    if (dealer_party_set.has(j))
      dealer_pids[j] = job.get_pid(j);
    else if (leaf_names.find(job.get_name(j)) == leaf_names.end())
      return coinbase::error(E_BADARG, "reshare: party is neither a dealer nor in the new access structure");
  }
  if (dealer_pids.empty()) return coinbase::error(E_BADARG, "reshare: no dealers");

  const bool is_dealer = dealer_party_set.has(i);
  const bool is_receiver = leaf_names.find(job.get_name(i)) != leaf_names.end();
  if (is_dealer && !q.is_in_range(additive_share)) return coinbase::error(E_BADARG, "reshare: invalid additive share");

  std::set<crypto::pname_t> node_names;
  collect_node_names(new_ac.root, node_names);
  std::string ac_encoding;
  encode_ac_node(new_ac.root, ac_encoding);

  if (sid.empty()) {
    if (rv = coinbase::mpc::generate_sid_fixed_mp(job, sid)) return coinbase::error(rv, "Failed to generate sid");
  }

  // All parties must agree on the curve, parties, dealers, expected Q, new structure and sid.
  auto h_consistency = job.uniform_msg<buf256_t>();
  h_consistency._i =
      crypto::sha256_t::hash(std::string("cbmpc-ec-reshare-ac-v1"), std::string(curve.get_name()), all_pids,
                             dealer_pids, Q, uint64_t(ac_encoding.size()), ac_encoding, uint64_t(sid.size()), sid);
  if (rv = job.plain_broadcast(h_consistency)) return coinbase::error(rv, "Failed to broadcast h_consistency");
  for (int j = 0; j < n; j++) {
    if (j == i) continue;
    if (h_consistency._j != h_consistency) return coinbase::error(E_CRYPTO, "reshare: h_consistency mismatch");
  }

  auto xij = job.nonuniform_msg<bn_t>();
  auto ac_pub_all = job.uniform_msg<ac_internal_pub_shares_t>();
  auto pi_r_all = job.uniform_msg<zk::uc_batch_dl_t>();
  auto c_all = job.uniform_msg<buf_t>();
  auto rho_all = job.uniform_msg<buf256_t>();

  crypto::commitment_t com_R(job.get_pid(i));

  if (is_dealer) {
    ac_internal_shares_t ac_internal_shares;
    ac_shares_t shares;
    if (rv = new_ac.share_with_internals(q, additive_share, shares, ac_internal_shares, ac_pub_all._i))
      return coinbase::error(rv, "Failed to share with internals");
    for (int j = 0; j < n; j++) {
      const auto it = shares.find(job.get_name(j));
      xij.msgs[j] = (it == shares.end()) ? bn_t(0) : it->second;
    }

    std::vector<bn_t> rs;
    std::vector<ecc_point_t> Rs;
    for (const auto& [node_name, internal_pub_share] : ac_pub_all._i) {
      rs.push_back(ac_internal_shares.at(node_name));
      Rs.push_back(internal_pub_share);
    }
    pi_r_all._i = zk::uc_batch_dl_t();
    pi_r_all._i.prove(Rs, rs, sid, i);

    com_R.gen(Rs, pi_r_all._i);
    c_all._i = com_R.msg;
    rho_all._i = com_R.rand;
  }

  if (rv = job.plain_broadcast(c_all)) return coinbase::error(rv, "Failed to broadcast c_all");

  // Every party (dealer or not) hashes the commitments it received; all hashes must agree, so a dealer cannot
  // show different commitments to different parties.
  auto h_all = job.uniform_msg<buf256_t>();
  std::map<party_idx_t, buf_t> received_cs;
  for (const auto& [j, _] : dealer_pids) received_cs[j] = c_all._j;
  h_all._i = crypto::sha256_t::hash(received_cs, dealer_pids, sid);

  if (rv = job.plain_broadcast(h_all, ac_pub_all, pi_r_all, rho_all, xij))
    return coinbase::error(rv, "Failed to broadcast h_all, ac_pub_all, pi_r_all, rho_all, xij");

  for (int j = 0; j < n; j++) {
    if (h_all._j != h_all._i) return coinbase::error(E_CRYPTO, "reshare: h_all mismatch");
  }

  ecc_point_t Q_sum = curve.infinity();
  ac_pub_shares_t Qis;
  for (const auto& name : leaf_names) Qis[name] = curve.infinity();
  bn_t x_i = 0;

  for (const auto& [j, dealer_pid] : dealer_pids) {
    const ac_internal_pub_shares_t& pub = ac_pub_all._j;

    // The public data must cover exactly the nodes of the agreed structure.
    if (pub.size() != node_names.size()) return coinbase::error(E_CRYPTO, "reshare: malformed public shares");
    for (const auto& name : node_names) {
      if (pub.find(name) == pub.end()) return coinbase::error(E_CRYPTO, "reshare: malformed public shares");
    }

    if (j != i) {
      std::vector<ecc_point_t> Rs;
      for (const auto& [node_name, internal_pub_share] : pub) Rs.push_back(internal_pub_share);
      crypto::commitment_t com_R_tag(dealer_pid);
      com_R_tag.set(rho_all._j, c_all._j);
      if (rv = com_R_tag.open(Rs, pi_r_all._j)) return coinbase::error(rv, "reshare: commitment does not open");
      for (const auto& R : Rs) {
        if (rv = curve.check(R)) return coinbase::error(rv, "reshare: R is not on the session curve");
      }
      if (rv = pi_r_all._j.verify(Rs, sid, j)) return coinbase::error(rv, "reshare: dl proof failed");
      // Every party checks the whole tree, so all honest parties accept the same public shares or abort.
      if (rv = verify_ac_pub_tree(new_ac.root, pub)) return rv;

      if (is_receiver) {
        // Feldman check of the received share against the dealer's committed tree.
        if (rv =
                new_ac.verify_share_against_ancestors_pub_data(pub.at(new_ac.root->name), xij._j, pub, job.get_name(i)))
          return coinbase::error(rv, "reshare: share does not match the dealer's commitments");
      }
    }

    {
      crypto::vartime_scope_t vartime_scope;
      Q_sum += pub.at(new_ac.root->name);
      for (const auto& name : leaf_names) Qis[name] += pub.at(name);
    }
    if (is_receiver) MODULO(q) x_i += xij._j;
  }

  if (Q_sum != Q) return coinbase::error(E_CRYPTO, "reshare: dealt shares do not sum to Q");

  {
    crypto::vartime_scope_t vartime_scope;
    ecc_point_t reconstructed_Q;
    if (rv = new_ac.reconstruct_exponent(Qis, reconstructed_Q))
      return coinbase::error(rv, "Failed to reconstruct exponent");
    if (reconstructed_Q != Q) return coinbase::error(E_CRYPTO, "reshare: public shares do not reconstruct Q");
  }

  if (!is_receiver) return SUCCESS;

  if (x_i * G != Qis.at(job.get_name(i))) return coinbase::error(E_CRYPTO, "reshare: x_i * G != Qi");

  new_key.x_share = x_i;
  new_key.Q = Q;
  new_key.Qis = std::move(Qis);
  new_key.curve = curve;
  new_key.party_name = job.get_name(i);
  has_new_key = true;
  return SUCCESS;
}

}  // namespace coinbase::mpc::eckey
