#pragma once

// Binary encoding of an access structure, as produced by `encodeAccessStructure` in src/access-structure.ts.
//
//   node      := LEAF name | AND children | OR children | THRESHOLD k children
//   LEAF      := u8 1, u32 len, len bytes (UTF-8 party name)
//   AND / OR  := u8 2 / u8 3, children
//   THRESHOLD := u8 4, u32 k, children
//   children  := u32 count, count * node
//
// Integers are big-endian. Shape rules (non-empty names, k range, ...) are checked by the library.
// Leaf names are views into the input buffer (`access_structure_t::leaf_name` is a string_view), so the decoded
// structure must not outlive it.

#include <cstdint>
#include <string_view>

#include <cbmpc/core/access_structure.h>
#include <cbmpc/core/buf.h>
#include <cbmpc/core/error.h>

namespace cbmpc_ts {

using coinbase::error_t;

class access_structure_decoder_t {
 public:
  explicit access_structure_decoder_t(coinbase::mem_t in) : p_(in.data), end_(in.data + in.size) {}

  error_t decode(coinbase::api::access_structure_t& out) {
    if (!p_ || p_ == end_) return E_BADARG;
    if (error_t rv = node(out, 0)) return rv;
    return p_ == end_ ? SUCCESS : E_BADARG;  // no trailing bytes
  }

 private:
  static constexpr int max_depth = 32;
  static constexpr uint32_t max_nodes = 1024;

  const uint8_t* p_;
  const uint8_t* end_;
  uint32_t nodes_ = 0;

  bool u8(uint8_t& v) {
    if (end_ - p_ < 1) return false;
    v = *p_++;
    return true;
  }
  bool u32(uint32_t& v) {
    if (end_ - p_ < 4) return false;
    v = (uint32_t(p_[0]) << 24) | (uint32_t(p_[1]) << 16) | (uint32_t(p_[2]) << 8) | uint32_t(p_[3]);
    p_ += 4;
    return true;
  }

  error_t node(coinbase::api::access_structure_t& out, int depth) {
    using ac_t = coinbase::api::access_structure_t;
    if (depth > max_depth || ++nodes_ > max_nodes) return E_RANGE;
    uint8_t type = 0;
    if (!u8(type)) return E_BADARG;
    if (type == 1) {
      uint32_t len = 0;
      if (!u32(len) || uint64_t(end_ - p_) < len) return E_BADARG;
      out = ac_t::leaf(std::string_view(reinterpret_cast<const char*>(p_), len));
      p_ += len;
      return SUCCESS;
    }
    uint32_t k = 0;
    if (type == 4 && !u32(k)) return E_BADARG;
    if (type < 2 || type > 4) return E_BADARG;
    uint32_t count = 0;
    if (!u32(count) || count > max_nodes) return E_BADARG;
    std::vector<ac_t> children(count);
    for (auto& child : children) {
      if (error_t rv = node(child, depth + 1)) return rv;
    }
    if (type == 2)
      out = ac_t::And(std::move(children));
    else if (type == 3)
      out = ac_t::Or(std::move(children));
    else {
      if (k > count) return E_BADARG;
      out = ac_t::Threshold(int(k), std::move(children));
    }
    return SUCCESS;
  }
};

}  // namespace cbmpc_ts
