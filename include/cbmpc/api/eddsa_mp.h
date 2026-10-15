#pragma once

#include <cbmpc/api/curve.h>
#include <cbmpc/core/access_structure.h>
#include <cbmpc/core/buf.h>
#include <cbmpc/core/error.h>
#include <cbmpc/core/job.h>

// All the functions have two versions: additive and ac. Additive means that the
// sharing is additive, while ac means that the sharing is according to a given access structure.
//
// Security note: key blobs contain private key-share material. See
// SECURE_USAGE.md for blob confidentiality, integrity, and trust-boundary
// requirements.
namespace coinbase::api::eddsa_mp {

// Run the multi-party key generation protocol for EdDSA.
//
// The output `key_blob` is a versioned, opaque byte string that can be persisted
// by the caller and used in other API calls.
//
// Supported curves: `curve_id::ed25519`.
error_t dkg_additive(const job_mp_t& job, curve_id curve, buf_t& key_blob, buf_t& sid);

// Run the multi-party key generation protocol for EdDSA with a
// general access structure.
//
// Notes:
// - This is an n-party protocol: **all** parties in
//   `job.party_names` must be online and participate.
// - Only the provided `quorum_party_names` actively contribute to the generated
//   key shares.
// - The output key blob represents an access-structure key share and
//   is not directly usable with `sign_additive()`. Use `sign_ac()` to sign with an online
//   quorum (it derives additive shares internally).
// - `sid` is an in/out session id used by the protocol. Callers may pass an
//   empty buffer to let the protocol derive one.
//
// Supported curves: `curve_id::ed25519`.
error_t dkg_ac(const job_mp_t& job, curve_id curve, buf_t& sid, const access_structure_t& access_structure,
               const std::vector<std::string_view>& quorum_party_names, buf_t& key_blob);

// Refresh an existing key share set, producing a new key share.
//
// `sid` is an in/out session id used by the refresh protocol. Callers may pass
// an empty buffer to let the protocol derive one.
error_t refresh_additive(const job_mp_t& job, buf_t& sid, mem_t key_blob, buf_t& new_key_blob);

// Refresh an existing key share set using the access-structure refresh protocol.
//
// Notes:
// - See `dkg_ac` for protocol participation semantics.
// - The output key blob represents an access-structure key share and
//   is not directly usable with `sign_additive()`. Use `sign_ac()` to sign with an online
//   quorum (it derives additive shares internally).
// - `sid` is an in/out session id used by the protocol. Callers may pass an
//   empty buffer to let the protocol derive one.
error_t refresh_ac(const job_mp_t& job, buf_t& sid, mem_t key_blob, const access_structure_t& access_structure,
                   const std::vector<std::string_view>& quorum_party_names, buf_t& new_key_blob);

// Sign a message with EdDSA-MP (Ed25519) and output signature on `sig_receiver`.
//
// Output signature is 64 bytes: R (32 bytes) || s (32 bytes).
//
// Note: the underlying protocol returns the signature only on `sig_receiver`. On
// other parties, `sig` may be left empty on success.
// On any error, `sig` is cleared.
error_t sign_additive(const job_mp_t& job, mem_t key_blob, mem_t msg, party_idx_t sig_receiver, buf_t& sig);

// Sign a message with EdDSA-MP (Ed25519) using an access-structure key share (from
// `dkg_ac` / `refresh_ac`).
//
// This API first derives an additive-share signing key for the **online** signing
// parties in `job.party_names` and then runs the normal `sign_additive()` protocol among
// those parties.
//
// Notes:
// - Unlike `dkg_ac` / `refresh_ac`, `sign_ac` only requires the parties in
//   `job.party_names` to be online and participate.
// - Output semantics match `sign_additive()`: the signature is returned only on
//   `sig_receiver`. On other parties, `sig` may be left empty on success.
// - On any error, `sig` is cleared.
error_t sign_ac(const job_mp_t& job, mem_t ac_key_blob, const access_structure_t& access_structure, mem_t msg,
                party_idx_t sig_receiver, buf_t& sig);

// Get the Ed25519 public key from a key blob.
//
// Output is the standard Ed25519 32-byte compressed public key encoding.
//
// Note: Ed25519 public keys are always encoded in this compressed format; the
// `_compressed` suffix is provided for naming consistency with ECDSA APIs.
error_t get_public_key_compressed(mem_t key_blob, buf_t& pub_key);

// ---------------------------------------------------------------------------
// Key blob manipulation (private scalar backup / restore)
// ---------------------------------------------------------------------------

// Get this party's share public point (Qi) from a key blob, returning the
// standard Ed25519 32-byte compressed public key encoding.
//
// This is useful for verifiable backup schemes like PVE, where a scalar x can be
// verified against its corresponding curve point Q = x*G.
//
// Notes:
// - Works for both additive (v1) and access-structure (v2) EdDSA-MP key blobs.
// - This can be called on a blob produced by `detach_private_scalar` since Qi_self
//   remains present in the key blob even after redaction.
error_t get_public_share_compressed(mem_t key_blob, buf_t& out_public_share_compressed);

// Detach the private scalar share from a key blob, producing:
// - a "public" key blob with its private scalar wiped, and
// - the private scalar x encoded as a fixed-length big-endian buffer.
//
// The public blob is safe to persist as public-only material, but is not usable
// for signing/refresh until restored with `attach_private_scalar`.
//
// Output:
// - `out_private_scalar_fixed` length equals the curve order size in bytes
//   (32 bytes for ed25519).
error_t detach_private_scalar(mem_t key_blob, buf_t& out_public_key_blob, buf_t& out_private_scalar_fixed);

// Restore a full key blob by attaching a fixed-length private scalar x into a
// public key blob (produced by `detach_private_scalar`).
//
// This validates that x matches the key blob by checking:
// - `public_share_compressed` matches the blob's Qi_self, and
// - x*G == Qi_self.
//
// Input:
// - `private_scalar_fixed` must be a fixed-length big-endian scalar encoding with
//   length equal to the curve order size in bytes (32 bytes for ed25519).
// - `public_share_compressed` must be the standard Ed25519 32-byte compressed point
//   encoding of this party's share public point (Qi_self), e.g. from `get_public_share_compressed`.
error_t attach_private_scalar(mem_t public_key_blob, mem_t private_scalar_fixed, mem_t public_share_compressed,
                              buf_t& out_key_blob);

// ---------------------------------------------------------------------------
// Resharing (fork addition)
// ---------------------------------------------------------------------------

// Reshare an existing key to a new access structure, keeping the public key.
//
// The input is an additive sharing of the private key held by `dealer_party_names` (for example both shares of a
// 2-of-2 key, or the outputs of `ac_key_to_additive_share` for a qualifying quorum of an access-structure key). Each
// dealer deals its share over `new_access_structure` with commitments and proofs; every receiver verifies its share
// against the commitments and that the dealt shares sum to `public_key_compressed`.
//
// Notes:
// - **All** parties in `job.party_names` must be online. Each one is a dealer, a leaf of `new_access_structure`, or
//   both; all of them must pass the same `public_key_compressed`, `dealer_party_names` and `new_access_structure`.
// - Dealers pass their additive share as a big-endian integer in `additive_share` (at most 64 bytes; it is reduced
//   modulo the curve order, so an unreduced ECDSA-2P P1 share is accepted). Non-dealers pass an empty buffer.
// - On success, parties in `new_access_structure` receive an access-structure key blob (usable with `sign_ac` and
//   `refresh_ac`); dealers outside it get an empty `new_ac_key_blob`.
// - Every party MUST take `public_key_compressed` from its own trusted record (dealers: the key they extracted the
//   share from; a new party without a key: the wallet's known public key / address), never from a peer or relay
//   message. A dealer that knows its peers' public shares can otherwise steer the honest parties into resharing a
//   different key, and deleting the old shares afterwards loses the real one.
// - Resharing does not revoke the old shares: any old qualifying set still reconstructs the same key. A malicious
//   dealer can make one receiver abort while others succeed, so treat the new generation as live only after every
//   party reported success; then delete the old key blobs (and old additive shares) and run `refresh_ac`.
// - Every party MUST also take `new_access_structure`, `dealer_party_names` and the mapping from party names to the
//   devices/people that hold them from its own record. The protocol only checks that all parties agree; it cannot
//   tell who runs a leaf, so a coordinator that hands everyone a structure in which it controls a qualifying set of
//   names gets the key.
// - Each dealer sends every receiver its sub-share in the clear inside the protocol messages. Pairwise messages MUST
//   be end-to-end encrypted between the two parties, and a relay operated by another party (e.g. a server that is
//   itself a receiver) MUST NOT be able to read them: with threshold 2, one intercepted sub-share plus the relay's own
//   reveals the dealer's additive share. The same holds for `dkg_ac` and `refresh_ac`.
// - `sid` is an in/out session id. Pass an empty buffer so the protocol derives a fresh one; a caller-supplied sid is
//   used as given and is not checked for freshness.
//
// Supported curves: `curve_id::ed25519`.
error_t reshare_from_additive(const job_mp_t& job, curve_id curve, buf_t& sid, mem_t public_key_compressed,
                              const std::vector<std::string_view>& dealer_party_names, mem_t additive_share,
                              const access_structure_t& new_access_structure, buf_t& new_ac_key_blob);

// Convert this party's access-structure key share into its additive share for `quorum_party_names`
// (Lagrange-weighted, fixed-length big-endian, curve order size). The additive shares of the parties of exactly that
// quorum sum to the private key; use them as `reshare_from_additive` input with the same quorum as dealers.
// The quorum must be a minimal qualifying set (e.g. 2 parties of a 2-of-3); a member that would get weight 0 is
// rejected with E_BADARG.
//
// The output is private key material, like the key blob itself.
error_t ac_key_to_additive_share(mem_t ac_key_blob, const access_structure_t& access_structure,
                                 const std::vector<std::string_view>& quorum_party_names,
                                 buf_t& out_additive_share_fixed);

}  // namespace coinbase::api::eddsa_mp
