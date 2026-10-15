// C API tests for cbmpc_{ecdsa,eddsa}_mp_reshare_from_additive (fork addition).
#include <cstring>
#include <gtest/gtest.h>
#include <memory>
#include <vector>

#include <cbmpc/c_api/access_structure.h>
#include <cbmpc/c_api/ecdsa_mp.h>
#include <cbmpc/c_api/eddsa_mp.h>
#include <cbmpc/c_api/job.h>
#include <cbmpc/core/error.h>
#include <cbmpc/internal/crypto/base_ecc.h>

#include "test_transport_harness.h"

namespace {

using coinbase::buf_t;
using coinbase::testutils::mpc_net_context_t;
using coinbase::testutils::capi_harness::make_transport;
using coinbase::testutils::capi_harness::run_mp;
using coinbase::testutils::capi_harness::transport_ctx_t;

struct c_ecdsa_t {
  static constexpr cbmpc_curve_id_t curve = CBMPC_CURVE_SECP256K1;
  static const coinbase::crypto::ecurve_t& icurve() { return coinbase::crypto::curve_secp256k1; }
  static constexpr auto dkg_ac = cbmpc_ecdsa_mp_dkg_ac;
  static constexpr auto sign_ac = cbmpc_ecdsa_mp_sign_ac;
  static constexpr auto pub = cbmpc_ecdsa_mp_get_public_key_compressed;
  static constexpr auto reshare = cbmpc_ecdsa_mp_reshare_from_additive;
  static constexpr auto to_additive = cbmpc_ecdsa_mp_ac_key_to_additive_share;
};
struct c_eddsa_t {
  static constexpr cbmpc_curve_id_t curve = CBMPC_CURVE_ED25519;
  static const coinbase::crypto::ecurve_t& icurve() { return coinbase::crypto::curve_ed25519; }
  static constexpr auto dkg_ac = cbmpc_eddsa_mp_dkg_ac;
  static constexpr auto sign_ac = cbmpc_eddsa_mp_sign_ac;
  static constexpr auto pub = cbmpc_eddsa_mp_get_public_key_compressed;
  static constexpr auto reshare = cbmpc_eddsa_mp_reshare_from_additive;
  static constexpr auto to_additive = cbmpc_eddsa_mp_ac_key_to_additive_share;
};

const char* kNames[3] = {"iphone", "mac", "server"};

// THRESHOLD[2](iphone, mac, server)
const int32_t kChildIndices[] = {1, 2, 3};
const cbmpc_access_structure_node_t kNodes[] = {
    {CBMPC_ACCESS_STRUCTURE_NODE_THRESHOLD, nullptr, 2, 0, 3},
    {CBMPC_ACCESS_STRUCTURE_NODE_LEAF, "iphone", 0, 0, 0},
    {CBMPC_ACCESS_STRUCTURE_NODE_LEAF, "mac", 0, 0, 0},
    {CBMPC_ACCESS_STRUCTURE_NODE_LEAF, "server", 0, 0, 0},
};
const cbmpc_access_structure_t kAc = {kNodes, 4, kChildIndices, 3, 0};

struct c_net_t {
  std::vector<std::shared_ptr<mpc_net_context_t>> peers;
  std::vector<transport_ctx_t> ctxs;
  std::vector<cbmpc_transport_t> transports;
  explicit c_net_t(int n) {
    for (int i = 0; i < n; i++) peers.push_back(std::make_shared<mpc_net_context_t>(i));
    for (const auto& p : peers) p->init_with_peers(peers);
    ctxs.resize(peers.size());
    transports.resize(peers.size());
    for (size_t i = 0; i < peers.size(); i++) {
      ctxs[i] = transport_ctx_t{peers[i], nullptr};
      transports[i] = make_transport(&ctxs[i]);
    }
  }
  cbmpc_mp_job_t job(int i, const char* const* names, int n) {
    return cbmpc_mp_job_t{i, names, n, &transports[static_cast<size_t>(i)]};
  }
};

template <typename Api>
bool pair_signs(const char* a, const char* b, cmem_t blob_a, cmem_t blob_b, cmem_t Q) {
  const char* names[2] = {a, b};
  const cmem_t blobs[2] = {blob_a, blob_b};
  uint8_t m[32];
  for (int i = 0; i < 32; i++) m[i] = static_cast<uint8_t>(i);
  c_net_t net(2);
  std::vector<cmem_t> sigs(2, cmem_t{nullptr, 0});
  std::vector<cbmpc_error_t> rvs;
  run_mp(
      net.peers,
      [&](int i) {
        const auto job = net.job(i, names, 2);
        return Api::sign_ac(&job, blobs[i], &kAc, cmem_t{m, 32}, 0, &sigs[static_cast<size_t>(i)]);
      },
      rvs);
  bool ok = rvs[0] == CBMPC_SUCCESS && rvs[1] == CBMPC_SUCCESS && sigs[0].size > 0;
  if (ok) {
    coinbase::crypto::ecc_point_t P;
    ok = P.from_bin(Api::icurve(), buf_t(Q.data, Q.size)) == SUCCESS &&
         coinbase::crypto::ecc_pub_key_t(P).verify(buf_t(m, 32), buf_t(sigs[0].data, sigs[0].size)) == SUCCESS;
  }
  for (auto s : sigs) cbmpc_cmem_free(s);
  return ok;
}

template <typename Api>
void dkg(std::vector<cmem_t>& blobs, cmem_t& Q) {
  c_net_t net(3);
  std::vector<cmem_t> sids(3, cmem_t{nullptr, 0});
  std::vector<cbmpc_error_t> rvs;
  blobs.assign(3, cmem_t{nullptr, 0});
  run_mp(
      net.peers,
      [&](int i) {
        const auto job = net.job(i, kNames, 3);
        return Api::dkg_ac(&job, Api::curve, cmem_t{nullptr, 0}, &kAc, kNames, 3, &blobs[static_cast<size_t>(i)],
                           &sids[static_cast<size_t>(i)]);
      },
      rvs);
  for (auto rv : rvs) ASSERT_EQ(rv, CBMPC_SUCCESS);
  for (auto s : sids) cbmpc_cmem_free(s);
  ASSERT_EQ(Api::pub(blobs[0], &Q), CBMPC_SUCCESS);
}

// Lost iphone: mac + server re-deal. Returns per-party errors.
template <typename Api>
std::vector<cbmpc_error_t> reshare_lost_device(const std::vector<cmem_t>& g0, cmem_t Q, std::vector<cmem_t>& g1) {
  const char* dealers[2] = {"mac", "server"};
  std::vector<cmem_t> xs(3, cmem_t{nullptr, 0});
  for (int i = 1; i < 3; i++)
    EXPECT_EQ(Api::to_additive(g0[size_t(i)], &kAc, dealers, 2, &xs[size_t(i)]), CBMPC_SUCCESS);
  c_net_t net(3);
  std::vector<cbmpc_error_t> rvs;
  g1.assign(3, cmem_t{nullptr, 0});
  run_mp(
      net.peers,
      [&](int i) {
        const auto job = net.job(i, kNames, 3);
        return Api::reshare(&job, Api::curve, cmem_t{nullptr, 0}, Q, dealers, 2, xs[size_t(i)], &kAc, nullptr,
                            &g1[size_t(i)]);
      },
      rvs);
  for (auto x : xs) cbmpc_cmem_free(x);
  return rvs;
}

template <typename T>
class CApiReshareAc : public ::testing::Test {};
using CAlgos = ::testing::Types<c_ecdsa_t, c_eddsa_t>;
TYPED_TEST_SUITE(CApiReshareAc, CAlgos);

}  // namespace

TYPED_TEST(CApiReshareAc, LostDeviceReshareThenEveryPairSigns) {
  using Api = TypeParam;
  std::vector<cmem_t> g0, g1;
  cmem_t Q{nullptr, 0};
  dkg<Api>(g0, Q);
  for (auto rv : reshare_lost_device<Api>(g0, Q, g1)) ASSERT_EQ(rv, CBMPC_SUCCESS);
  for (int i = 0; i < 3; i++) {
    cmem_t q2{nullptr, 0};
    ASSERT_EQ(Api::pub(g1[size_t(i)], &q2), CBMPC_SUCCESS);
    ASSERT_EQ(q2.size, Q.size);
    EXPECT_EQ(std::memcmp(q2.data, Q.data, size_t(Q.size)), 0);
    cbmpc_cmem_free(q2);
  }
  EXPECT_TRUE(pair_signs<Api>("iphone", "server", g1[0], g1[2], Q));
  EXPECT_TRUE(pair_signs<Api>("mac", "server", g1[1], g1[2], Q));
  EXPECT_TRUE(pair_signs<Api>("iphone", "mac", g1[0], g1[1], Q));
  EXPECT_FALSE(pair_signs<Api>("iphone", "server", g0[0], g1[2], Q));
  for (auto b : g0) cbmpc_cmem_free(b);
  for (auto b : g1) cbmpc_cmem_free(b);
  cbmpc_cmem_free(Q);
}

TYPED_TEST(CApiReshareAc, WrongPublicKeyRejected) {
  using Api = TypeParam;
  std::vector<cmem_t> g0, other, g1;
  cmem_t Q{nullptr, 0}, other_Q{nullptr, 0};
  dkg<Api>(g0, Q);
  dkg<Api>(other, other_Q);
  for (auto rv : reshare_lost_device<Api>(g0, other_Q, g1)) EXPECT_NE(rv, CBMPC_SUCCESS);
  for (auto b : g1) EXPECT_EQ(b.data, nullptr);
  for (auto b : g0) cbmpc_cmem_free(b);
  for (auto b : other) cbmpc_cmem_free(b);
  cbmpc_cmem_free(Q);
  cbmpc_cmem_free(other_Q);
}
