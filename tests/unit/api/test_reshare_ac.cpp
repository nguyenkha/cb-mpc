// Tests for {ecdsa,eddsa}_mp::reshare_from_additive (fork addition).
// Roles follow the kexify 2-of-3 layout: "iphone" (device), "mac" (backup), "server".
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

#include <cbmpc/api/ecdsa_2p.h>
#include <cbmpc/api/ecdsa_mp.h>
#include <cbmpc/api/eddsa_2p.h>
#include <cbmpc/api/eddsa_mp.h>
#include <cbmpc/core/access_structure.h>
#include <cbmpc/internal/crypto/base_ecc.h>

#include "test_transport_harness.h"

namespace {

using coinbase::buf_t;
using coinbase::error_t;
using coinbase::mem_t;
using coinbase::api::access_structure_t;
using coinbase::api::curve_id;
using coinbase::api::data_transport_i;
using coinbase::api::job_2p_t;
using coinbase::api::job_mp_t;
using coinbase::api::party_2p_t;
using coinbase::api::party_idx_t;
using coinbase::testutils::mpc_net_context_t;
using coinbase::testutils::api_harness::local_api_transport_t;
using coinbase::testutils::api_harness::run_mp;
using names_t = std::vector<std::string_view>;

const std::string_view kIphone = "iphone", kMac = "mac", kServer = "server";
const names_t kAll = {kIphone, kMac, kServer};

access_structure_t threshold_of(int k, const names_t& names) {
  std::vector<access_structure_t> leaves;
  for (auto n : names) leaves.push_back(access_structure_t::leaf(n));
  return access_structure_t::Threshold(k, leaves);
}
const access_structure_t kTwoOfThree = threshold_of(2, kAll);

// Flips the last byte of the `index`-th message (0-based) this party sends to `victim`.
class tamper_transport_t final : public data_transport_i {
 public:
  tamper_transport_t(std::shared_ptr<mpc_net_context_t> ctx, party_idx_t victim, int index)
      : inner_(std::move(ctx)), victim_(victim), index_(index) {}
  error_t send(party_idx_t r, mem_t m) override {
    if (r == victim_ && sent_to_victim_++ == index_ && m.size > 0) {
      buf_t t(m);
      t[t.size() - 1] ^= 0x01;
      return inner_.send(r, t);
    }
    return inner_.send(r, m);
  }
  error_t receive(party_idx_t s, buf_t& m) override { return inner_.receive(s, m); }
  error_t receive_all(const std::vector<party_idx_t>& s, std::vector<buf_t>& m) override {
    return inner_.receive_all(s, m);
  }
  int sent_to_victim() const { return sent_to_victim_; }

 private:
  local_api_transport_t inner_;
  party_idx_t victim_;
  int index_;
  int sent_to_victim_ = 0;
};

struct net_t {
  std::vector<std::shared_ptr<mpc_net_context_t>> peers;
  std::vector<std::unique_ptr<data_transport_i>> transports;
  explicit net_t(int n) {
    for (int i = 0; i < n; i++) peers.push_back(std::make_shared<mpc_net_context_t>(i));
    for (const auto& p : peers) p->init_with_peers(peers);
    for (const auto& p : peers) transports.push_back(std::make_unique<local_api_transport_t>(p));
  }
  template <typename F>
  std::vector<error_t> run(F&& f) {
    std::vector<error_t> rvs;
    run_mp(peers, [&](int i) { return f(i, *transports[static_cast<size_t>(i)]); }, rvs);
    return rvs;
  }
};

buf_t msg32() {
  buf_t m(32);
  for (int i = 0; i < m.size(); i++) m[i] = static_cast<uint8_t>(0xA0 + i);
  return m;
}

struct ecdsa_t {
  static constexpr curve_id cid = curve_id::secp256k1;
  static const coinbase::crypto::ecurve_t& curve() { return coinbase::crypto::curve_secp256k1; }
  static error_t dkg_2p(const job_2p_t& j, buf_t& out) { return coinbase::api::ecdsa_2p::dkg(j, cid, out); }
  static error_t refresh_2p(const job_2p_t& j, mem_t in, buf_t& out) {
    return coinbase::api::ecdsa_2p::refresh(j, in, out);
  }
  static error_t pub_2p(mem_t b, buf_t& q) { return coinbase::api::ecdsa_2p::get_public_key_compressed(b, q); }
  static error_t detach_2p(mem_t b, buf_t& pub, buf_t& x) {
    return coinbase::api::ecdsa_2p::detach_private_scalar(b, pub, x);
  }
  static error_t dkg_ac(const job_mp_t& j, buf_t& sid, const access_structure_t& ac, const names_t& q, buf_t& out) {
    return coinbase::api::ecdsa_mp::dkg_ac(j, cid, sid, ac, q, out);
  }
  static error_t refresh_ac(const job_mp_t& j, buf_t& sid, mem_t b, const access_structure_t& ac, const names_t& q,
                            buf_t& out) {
    return coinbase::api::ecdsa_mp::refresh_ac(j, sid, b, ac, q, out);
  }
  static error_t sign_ac(const job_mp_t& j, mem_t b, const access_structure_t& ac, mem_t m, buf_t& sig) {
    return coinbase::api::ecdsa_mp::sign_ac(j, b, ac, m, 0, sig);
  }
  static error_t reshare(const job_mp_t& j, buf_t& sid, mem_t Q, const names_t& dealers, mem_t x,
                         const access_structure_t& ac, buf_t& out) {
    return coinbase::api::ecdsa_mp::reshare_from_additive(j, cid, sid, Q, dealers, x, ac, out);
  }
  static error_t to_additive(mem_t b, const access_structure_t& ac, const names_t& q, buf_t& x) {
    return coinbase::api::ecdsa_mp::ac_key_to_additive_share(b, ac, q, x);
  }
  static error_t pub(mem_t b, buf_t& q) { return coinbase::api::ecdsa_mp::get_public_key_compressed(b, q); }
  static error_t pub_share(mem_t b, buf_t& q) { return coinbase::api::ecdsa_mp::get_public_share_compressed(b, q); }
  static error_t detach(mem_t b, buf_t& pub, buf_t& x) {
    return coinbase::api::ecdsa_mp::detach_private_scalar(b, pub, x);
  }
  static error_t attach(mem_t pub, mem_t x, mem_t Qi, buf_t& out) {
    return coinbase::api::ecdsa_mp::attach_private_scalar(pub, x, Qi, out);
  }
};

struct eddsa_t {
  static constexpr curve_id cid = curve_id::ed25519;
  static const coinbase::crypto::ecurve_t& curve() { return coinbase::crypto::curve_ed25519; }
  static error_t dkg_2p(const job_2p_t& j, buf_t& out) { return coinbase::api::eddsa_2p::dkg(j, cid, out); }
  static error_t refresh_2p(const job_2p_t& j, mem_t in, buf_t& out) {
    return coinbase::api::eddsa_2p::refresh(j, in, out);
  }
  static error_t pub_2p(mem_t b, buf_t& q) { return coinbase::api::eddsa_2p::get_public_key_compressed(b, q); }
  static error_t detach_2p(mem_t b, buf_t& pub, buf_t& x) {
    return coinbase::api::eddsa_2p::detach_private_scalar(b, pub, x);
  }
  static error_t dkg_ac(const job_mp_t& j, buf_t& sid, const access_structure_t& ac, const names_t& q, buf_t& out) {
    return coinbase::api::eddsa_mp::dkg_ac(j, cid, sid, ac, q, out);
  }
  static error_t refresh_ac(const job_mp_t& j, buf_t& sid, mem_t b, const access_structure_t& ac, const names_t& q,
                            buf_t& out) {
    return coinbase::api::eddsa_mp::refresh_ac(j, sid, b, ac, q, out);
  }
  static error_t sign_ac(const job_mp_t& j, mem_t b, const access_structure_t& ac, mem_t m, buf_t& sig) {
    return coinbase::api::eddsa_mp::sign_ac(j, b, ac, m, 0, sig);
  }
  static error_t reshare(const job_mp_t& j, buf_t& sid, mem_t Q, const names_t& dealers, mem_t x,
                         const access_structure_t& ac, buf_t& out) {
    return coinbase::api::eddsa_mp::reshare_from_additive(j, cid, sid, Q, dealers, x, ac, out);
  }
  static error_t to_additive(mem_t b, const access_structure_t& ac, const names_t& q, buf_t& x) {
    return coinbase::api::eddsa_mp::ac_key_to_additive_share(b, ac, q, x);
  }
  static error_t pub(mem_t b, buf_t& q) { return coinbase::api::eddsa_mp::get_public_key_compressed(b, q); }
  static error_t pub_share(mem_t b, buf_t& q) { return coinbase::api::eddsa_mp::get_public_share_compressed(b, q); }
  static error_t detach(mem_t b, buf_t& pub, buf_t& x) {
    return coinbase::api::eddsa_mp::detach_private_scalar(b, pub, x);
  }
  static error_t attach(mem_t pub, mem_t x, mem_t Qi, buf_t& out) {
    return coinbase::api::eddsa_mp::attach_private_scalar(pub, x, Qi, out);
  }
};

// Party key material by name.
using keys_t = std::map<std::string, buf_t>;

template <typename Api>
bool signs(const names_t& pair, const keys_t& keys, const access_structure_t& ac, mem_t Q_bin) {
  net_t net(2);
  std::vector<buf_t> sigs(2);
  auto rvs = net.run([&](int i, data_transport_i& t) {
    job_mp_t job{static_cast<party_idx_t>(i), pair, t};
    return Api::sign_ac(job, keys.at(std::string(pair[static_cast<size_t>(i)])), ac, msg32(), sigs[size_t(i)]);
  });
  for (auto rv : rvs)
    if (rv) return false;
  coinbase::crypto::ecc_point_t Q;
  if (Q.from_bin(Api::curve(), Q_bin)) return false;
  return sigs[0].size() > 0 && coinbase::crypto::ecc_pub_key_t(Q).verify(msg32(), sigs[0]) == SUCCESS;
}

template <typename Api>
void expect_every_pair_signs(const names_t& parties, const keys_t& keys, const access_structure_t& ac, mem_t Q) {
  for (size_t a = 0; a < parties.size(); a++)
    for (size_t b = a + 1; b < parties.size(); b++)
      EXPECT_TRUE(signs<Api>({parties[a], parties[b]}, keys, ac, Q)) << parties[a] << "+" << parties[b];
}

// Runs reshare over `job_names`; `inputs` maps dealers to their additive shares. Returns per-party errors.
template <typename Api>
std::vector<error_t> reshare(const names_t& job_names, const names_t& dealers, const keys_t& inputs, mem_t Q,
                             const access_structure_t& new_ac, keys_t& out, net_t* custom_net = nullptr) {
  net_t default_net(static_cast<int>(job_names.size()));
  net_t& net = custom_net ? *custom_net : default_net;
  std::vector<buf_t> blobs(job_names.size());
  auto rvs = net.run([&](int i, data_transport_i& t) {
    job_mp_t job{static_cast<party_idx_t>(i), job_names, t};
    buf_t sid;
    const auto it = inputs.find(std::string(job_names[size_t(i)]));
    const mem_t x = it == inputs.end() ? mem_t() : mem_t(it->second);
    return Api::reshare(job, sid, Q, dealers, x, new_ac, blobs[size_t(i)]);
  });
  for (size_t i = 0; i < job_names.size(); i++)
    if (rvs[i] == SUCCESS && blobs[i].size() > 0) out[std::string(job_names[i])] = blobs[i];
  return rvs;
}

template <typename Api>
keys_t refresh_all(const names_t& parties, const keys_t& keys, const access_structure_t& ac) {
  net_t net(static_cast<int>(parties.size()));
  std::vector<buf_t> fresh(parties.size());
  auto rvs = net.run([&](int i, data_transport_i& t) {
    job_mp_t job{static_cast<party_idx_t>(i), parties, t};
    buf_t sid;
    return Api::refresh_ac(job, sid, keys.at(std::string(parties[size_t(i)])), ac, parties, fresh[size_t(i)]);
  });
  keys_t out;
  for (size_t i = 0; i < parties.size(); i++) {
    EXPECT_EQ(rvs[i], SUCCESS);
    out[std::string(parties[i])] = fresh[i];
  }
  return out;
}

template <typename Api>
keys_t dkg_2of3(buf_t& Q) {
  net_t net(3);
  std::vector<buf_t> blobs(3);
  auto rvs = net.run([&](int i, data_transport_i& t) {
    job_mp_t job{static_cast<party_idx_t>(i), kAll, t};
    buf_t sid;
    return Api::dkg_ac(job, sid, kTwoOfThree, kAll, blobs[size_t(i)]);
  });
  keys_t keys;
  for (size_t i = 0; i < 3; i++) {
    EXPECT_EQ(rvs[i], SUCCESS);
    keys[std::string(kAll[i])] = blobs[i];
  }
  EXPECT_EQ(Api::pub(blobs[0], Q), SUCCESS);
  return keys;
}

// A 2P key between "iphone" (p1) and "server" (p2), refreshed twice so an ECDSA P1 share can exceed q.
// Returns the additive shares keyed by the new party names.
template <typename Api>
keys_t two_party_shares(buf_t& Q) {
  auto peers = std::vector<std::shared_ptr<mpc_net_context_t>>{std::make_shared<mpc_net_context_t>(0),
                                                               std::make_shared<mpc_net_context_t>(1)};
  for (auto& p : peers) p->init_with_peers(peers);
  local_api_transport_t t0(peers[0]), t1(peers[1]);
  std::vector<buf_t> k(2);
  std::vector<error_t> rvs;
  auto job = [&](int i) {
    return job_2p_t{i == 0 ? party_2p_t::p1 : party_2p_t::p2, "iphone", "server",
                    i == 0 ? static_cast<data_transport_i&>(t0) : t1};
  };
  run_mp(peers, [&](int i) { return Api::dkg_2p(job(i), k[size_t(i)]); }, rvs);
  for (auto rv : rvs) EXPECT_EQ(rv, SUCCESS);
  for (int r = 0; r < 2; r++) {
    std::vector<buf_t> nk(2);
    run_mp(peers, [&](int i) { return Api::refresh_2p(job(i), k[size_t(i)], nk[size_t(i)]); }, rvs);
    for (auto rv : rvs) EXPECT_EQ(rv, SUCCESS);
    k = nk;
  }
  EXPECT_EQ(Api::pub_2p(k[0], Q), SUCCESS);
  keys_t xs;
  for (int i = 0; i < 2; i++) {
    buf_t pub, x;
    EXPECT_EQ(Api::detach_2p(k[size_t(i)], pub, x), SUCCESS);
    xs[i == 0 ? "iphone" : "server"] = x;
  }
  return xs;
}

template <typename Api>
keys_t additive_shares(const keys_t& keys, const names_t& quorum) {
  keys_t xs;
  for (auto name : quorum) {
    buf_t x;
    EXPECT_EQ(Api::to_additive(keys.at(std::string(name)), kTwoOfThree, quorum, x), SUCCESS);
    xs[std::string(name)] = x;
  }
  return xs;
}

template <typename T>
class ApiReshareAc : public ::testing::Test {};
using Algos = ::testing::Types<ecdsa_t, eddsa_t>;
TYPED_TEST_SUITE(ApiReshareAc, Algos);

}  // namespace

// 2-of-2 (iphone + server) -> 2-of-3 (iphone, mac, server); mac only receives.
TYPED_TEST(ApiReshareAc, TwoPartyToTwoOfThreeKeepsKey) {
  using Api = TypeParam;
  buf_t Q;
  const keys_t xs = two_party_shares<Api>(Q);
  keys_t keys;
  for (auto rv : reshare<Api>(kAll, {kIphone, kServer}, xs, Q, kTwoOfThree, keys)) ASSERT_EQ(rv, SUCCESS);
  ASSERT_EQ(keys.size(), 3u);
  for (const auto& [name, blob] : keys) {
    buf_t q2;
    ASSERT_EQ(Api::pub(blob, q2), SUCCESS);
    EXPECT_EQ(q2, Q) << name;
  }
  expect_every_pair_signs<Api>(kAll, keys, kTwoOfThree, Q);
  const keys_t fresh = refresh_all<Api>(kAll, keys, kTwoOfThree);
  expect_every_pair_signs<Api>(kAll, fresh, kTwoOfThree, Q);
}

// An unreduced share (as an ECDSA-2P P1 Paillier-plaintext share can be) is reduced mod q.
TYPED_TEST(ApiReshareAc, UnreducedShareAccepted) {
  using Api = TypeParam;
  buf_t Q;
  keys_t xs = two_party_shares<Api>(Q);
  const auto& q = Api::curve().order();
  xs["iphone"] = (coinbase::crypto::bn_t::from_bin(xs.at("iphone")) + q.value() + q.value()).to_bin();
  ASSERT_GT(xs.at("iphone").size(), 0);
  keys_t keys;
  for (auto rv : reshare<Api>(kAll, {kIphone, kServer}, xs, Q, kTwoOfThree, keys)) ASSERT_EQ(rv, SUCCESS);
  EXPECT_TRUE(signs<Api>({kMac, kServer}, keys, kTwoOfThree, Q));
}

// iPhone lost: mac (backup) + server re-deal a new generation for {new iphone, mac, server}.
TYPED_TEST(ApiReshareAc, LostDeviceReplacedByBackupAndServer) {
  using Api = TypeParam;
  buf_t Q;
  const keys_t g0 = dkg_2of3<Api>(Q);
  const keys_t xs = additive_shares<Api>(g0, {kMac, kServer});
  keys_t g1;
  for (auto rv : reshare<Api>(kAll, {kMac, kServer}, xs, Q, kTwoOfThree, g1)) ASSERT_EQ(rv, SUCCESS);
  ASSERT_EQ(g1.size(), 3u);
  expect_every_pair_signs<Api>(kAll, g1, kTwoOfThree, Q);

  // The lost device's old share does not combine with the new generation.
  keys_t mixed = {{"iphone", g0.at("iphone")}, {"server", g1.at("server")}};
  EXPECT_FALSE(signs<Api>({kIphone, kServer}, mixed, kTwoOfThree, Q));

  const keys_t fresh = refresh_all<Api>(kAll, g1, kTwoOfThree);
  expect_every_pair_signs<Api>(kAll, fresh, kTwoOfThree, Q);
}

// 2-of-3 -> 2-of-2 with the dealers being the new parties.
TYPED_TEST(ApiReshareAc, TwoOfThreeToTwoOfTwo) {
  using Api = TypeParam;
  buf_t Q;
  const keys_t g0 = dkg_2of3<Api>(Q);
  const names_t pair = {kIphone, kServer};
  const access_structure_t two_of_two = threshold_of(2, pair);
  keys_t g1;
  for (auto rv : reshare<Api>(pair, pair, additive_shares<Api>(g0, pair), Q, two_of_two, g1)) ASSERT_EQ(rv, SUCCESS);
  ASSERT_EQ(g1.size(), 2u);
  EXPECT_TRUE(signs<Api>(pair, g1, two_of_two, Q));
  const keys_t fresh = refresh_all<Api>(pair, g1, two_of_two);
  EXPECT_TRUE(signs<Api>(pair, fresh, two_of_two, Q));
}

// A dealer outside the new structure (mac deals, then drops out) gets no output.
TYPED_TEST(ApiReshareAc, DealerOutsideNewStructureGetsNoKey) {
  using Api = TypeParam;
  buf_t Q;
  const keys_t g0 = dkg_2of3<Api>(Q);
  const names_t dealers = {kMac, kServer};
  const access_structure_t two_of_two = threshold_of(2, {kIphone, kServer});
  keys_t g1;
  for (auto rv : reshare<Api>(kAll, dealers, additive_shares<Api>(g0, dealers), Q, two_of_two, g1))
    ASSERT_EQ(rv, SUCCESS);
  ASSERT_EQ(g1.size(), 2u);
  EXPECT_EQ(g1.count("mac"), 0u);
  EXPECT_TRUE(signs<Api>({kIphone, kServer}, g1, two_of_two, Q));
}

TYPED_TEST(ApiReshareAc, WrongPublicKeyRejected) {
  using Api = TypeParam;
  buf_t Q, other_Q;
  const keys_t g0 = dkg_2of3<Api>(Q);
  dkg_2of3<Api>(other_Q);
  keys_t g1;
  for (auto rv :
       reshare<Api>(kAll, {kMac, kServer}, additive_shares<Api>(g0, {kMac, kServer}), other_Q, kTwoOfThree, g1))
    EXPECT_NE(rv, SUCCESS);
  EXPECT_TRUE(g1.empty());
}

// A dealer that deals a share other than its real one (here x + 1) makes the sum miss Q.
TYPED_TEST(ApiReshareAc, WrongDealerShareRejected) {
  using Api = TypeParam;
  buf_t Q;
  const keys_t g0 = dkg_2of3<Api>(Q);
  keys_t xs = additive_shares<Api>(g0, {kMac, kServer});
  buf_t& x = xs.at("mac");
  x[x.size() - 1] ^= 0x01;
  keys_t g1;
  for (auto rv : reshare<Api>(kAll, {kMac, kServer}, xs, Q, kTwoOfThree, g1)) EXPECT_NE(rv, SUCCESS);
  EXPECT_TRUE(g1.empty());
}

// The quorum used for the Lagrange conversion must be the dealer set.
TYPED_TEST(ApiReshareAc, MismatchedQuorumConversionRejected) {
  using Api = TypeParam;
  buf_t Q;
  const keys_t g0 = dkg_2of3<Api>(Q);
  keys_t xs = additive_shares<Api>(g0, {kMac, kServer});
  xs["mac"] = additive_shares<Api>(g0, {kIphone, kMac}).at("mac");
  keys_t g1;
  for (auto rv : reshare<Api>(kAll, {kMac, kServer}, xs, Q, kTwoOfThree, g1)) EXPECT_NE(rv, SUCCESS);
  EXPECT_TRUE(g1.empty());
}

// A dealer's commitment (message 1) or opening/shares bundle (message 2) altered in transit to one receiver.
TYPED_TEST(ApiReshareAc, TamperedDealerMessagesRejected) {
  using Api = TypeParam;
  buf_t Q;
  const keys_t g0 = dkg_2of3<Api>(Q);
  const keys_t xs = additive_shares<Api>(g0, {kMac, kServer});
  // Count the sends from "mac" (index 1) to "iphone" (index 0) in an honest run; the last two are the commitment
  // round and the opening/proof/shares round.
  int total = 0;
  {
    net_t net(3);
    auto counter = std::make_unique<tamper_transport_t>(net.peers[1], /*victim=*/0, /*index=*/-1);
    auto* c = counter.get();
    net.transports[1] = std::move(counter);
    keys_t g1;
    for (auto rv : reshare<Api>(kAll, {kMac, kServer}, xs, Q, kTwoOfThree, g1, &net)) ASSERT_EQ(rv, SUCCESS);
    total = c->sent_to_victim();
  }
  ASSERT_GE(total, 3);
  for (int index : {total - 2, total - 1}) {
    net_t net(3);
    net.transports[1] = std::make_unique<tamper_transport_t>(net.peers[1], /*victim=*/0, index);
    keys_t g1;
    auto rvs = reshare<Api>(kAll, {kMac, kServer}, xs, Q, kTwoOfThree, g1, &net);
    EXPECT_NE(rvs[0], SUCCESS) << "tampered message " << index << " accepted";
    EXPECT_EQ(g1.count("iphone"), 0u);
  }
}

TYPED_TEST(ApiReshareAc, DisagreeingNewStructureRejected) {
  using Api = TypeParam;
  buf_t Q;
  const keys_t g0 = dkg_2of3<Api>(Q);
  const keys_t xs = additive_shares<Api>(g0, {kMac, kServer});
  net_t net(3);
  std::vector<buf_t> blobs(3);
  auto rvs = net.run([&](int i, data_transport_i& t) {
    job_mp_t job{static_cast<party_idx_t>(i), kAll, t};
    buf_t sid;
    const auto ac = i == 0 ? threshold_of(3, kAll) : kTwoOfThree;  // iphone expects 3-of-3
    const auto it = xs.find(std::string(kAll[size_t(i)]));
    return Api::reshare(job, sid, Q, {kMac, kServer}, it == xs.end() ? mem_t() : mem_t(it->second), ac,
                        blobs[size_t(i)]);
  });
  for (auto rv : rvs) EXPECT_NE(rv, SUCCESS);
}

TYPED_TEST(ApiReshareAc, BadArgumentsRejected) {
  using Api = TypeParam;
  buf_t Q;
  const keys_t g0 = dkg_2of3<Api>(Q);
  keys_t xs = additive_shares<Api>(g0, {kMac, kServer});
  keys_t out;
  // Non-dealer passing a share.
  xs["iphone"] = xs.at("mac");
  for (auto rv : reshare<Api>(kAll, {kMac, kServer}, xs, Q, kTwoOfThree, out)) EXPECT_NE(rv, SUCCESS);
  // Dealer missing its share.
  xs.erase("iphone");
  xs.erase("mac");
  for (auto rv : reshare<Api>(kAll, {kMac, kServer}, xs, Q, kTwoOfThree, out)) EXPECT_NE(rv, SUCCESS);
  // A dealer share that reduces to 0.
  xs = additive_shares<Api>(g0, {kMac, kServer});
  xs["mac"] = buf_t(32);
  for (int i = 0; i < 32; i++) xs["mac"][i] = 0;
  for (auto rv : reshare<Api>(kAll, {kMac, kServer}, xs, Q, kTwoOfThree, out)) EXPECT_NE(rv, SUCCESS);
  // New structure names a party that is not in the job.
  xs = additive_shares<Api>(g0, {kMac, kServer});
  const access_structure_t foreign = threshold_of(2, {kMac, kServer, "watch"});
  for (auto rv : reshare<Api>(kAll, {kMac, kServer}, xs, Q, foreign, out)) EXPECT_NE(rv, SUCCESS);
  EXPECT_TRUE(out.empty());
  // Converting with a quorum that does not include the key owner.
  buf_t x;
  EXPECT_NE(Api::to_additive(g0.at("iphone"), kTwoOfThree, {kMac, kServer}, x), SUCCESS);
}

// The backup's share cannot sign as the device.
TYPED_TEST(ApiReshareAc, BackupCannotImpersonateDevice) {
  using Api = TypeParam;
  buf_t Q;
  const keys_t g0 = dkg_2of3<Api>(Q);
  keys_t g1;
  for (auto rv : reshare<Api>(kAll, {kMac, kServer}, additive_shares<Api>(g0, {kMac, kServer}), Q, kTwoOfThree, g1))
    ASSERT_EQ(rv, SUCCESS);

  // 1. The mac blob presented as "iphone".
  keys_t as_iphone = {{"iphone", g1.at("mac")}, {"server", g1.at("server")}};
  EXPECT_FALSE(signs<Api>({kIphone, kServer}, as_iphone, kTwoOfThree, Q));

  // 2. The mac scalar grafted into the iphone blob.
  buf_t iphone_pub, iphone_x, mac_pub, mac_x, iphone_Qi, grafted;
  ASSERT_EQ(Api::detach(g1.at("iphone"), iphone_pub, iphone_x), SUCCESS);
  ASSERT_EQ(Api::detach(g1.at("mac"), mac_pub, mac_x), SUCCESS);
  ASSERT_EQ(Api::pub_share(g1.at("iphone"), iphone_Qi), SUCCESS);
  EXPECT_NE(Api::attach(iphone_pub, mac_x, iphone_Qi, grafted), SUCCESS);
}

// Nested structure: server AND (iphone OR mac). Reshare from 2-of-3 into it; server+device signs, devices alone don't.
TYPED_TEST(ApiReshareAc, ReshareIntoNestedStructure) {
  using Api = TypeParam;
  buf_t Q;
  const keys_t g0 = dkg_2of3<Api>(Q);
  const access_structure_t nested = access_structure_t::And(
      {access_structure_t::leaf(kServer),
       access_structure_t::Or({access_structure_t::leaf(kIphone), access_structure_t::leaf(kMac)})});
  keys_t g1;
  for (auto rv : reshare<Api>(kAll, {kMac, kServer}, additive_shares<Api>(g0, {kMac, kServer}), Q, nested, g1))
    ASSERT_EQ(rv, SUCCESS);
  ASSERT_EQ(g1.size(), 3u);
  EXPECT_TRUE(signs<Api>({kIphone, kServer}, g1, nested, Q));
  EXPECT_TRUE(signs<Api>({kMac, kServer}, g1, nested, Q));
  EXPECT_FALSE(signs<Api>({kIphone, kMac}, g1, nested, Q));
  const keys_t fresh = refresh_all<Api>(kAll, g1, nested);
  EXPECT_TRUE(signs<Api>({kMac, kServer}, fresh, nested, Q));
}

// A full 2-of-3 quorum as dealers gives one member weight 0: rejected with a clear error at conversion time.
TYPED_TEST(ApiReshareAc, ZeroWeightQuorumMemberRejected) {
  using Api = TypeParam;
  buf_t Q;
  const keys_t g0 = dkg_2of3<Api>(Q);
  int rejected = 0;
  for (auto name : kAll) {
    buf_t x;
    rejected += Api::to_additive(g0.at(std::string(name)), kTwoOfThree, kAll, x) == E_BADARG;
  }
  EXPECT_EQ(rejected, 1);
}

// A job party that neither deals nor is in the new structure is rejected.
TYPED_TEST(ApiReshareAc, BystanderPartyRejected) {
  using Api = TypeParam;
  buf_t Q;
  const keys_t g0 = dkg_2of3<Api>(Q);
  const names_t pair = {kMac, kServer};
  keys_t g1;
  for (auto rv : reshare<Api>(kAll, pair, additive_shares<Api>(g0, pair), Q, threshold_of(2, pair), g1))
    EXPECT_NE(rv, SUCCESS);
  EXPECT_TRUE(g1.empty());
}
