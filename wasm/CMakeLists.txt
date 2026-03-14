cmake_minimum_required(VERSION 3.16)

project(cbmpc_wasm LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ------------- Paths -----------------------------------------------------------

set(ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/..)
set(SRC_DIR ${ROOT_DIR}/src)
set(CGO_DIR ${ROOT_DIR}/demos-go/cb-mpc-go/internal/cgobinding)

include(${ROOT_DIR}/cmake/macros.cmake)

# ------------- OpenSSL for WASM ------------------------------------------------

set(CBMPC_OPENSSL_ROOT "$ENV{CBMPC_OPENSSL_ROOT}")
if(NOT CBMPC_OPENSSL_ROOT)
  set(CBMPC_OPENSSL_ROOT "/usr/local/opt/openssl@3.2.0-wasm")
endif()

set(OPENSSL_INCLUDE "${CBMPC_OPENSSL_ROOT}/include")
set(OPENSSL_LIB "${CBMPC_OPENSSL_ROOT}/lib/libcrypto.a")

if(NOT EXISTS "${OPENSSL_LIB}")
  message(FATAL_ERROR
    "WASM OpenSSL not found at ${OPENSSL_LIB}.\n"
    "Build it first: make openssl-wasm")
endif()

# ------------- Compilation flags -----------------------------------------------

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -fPIC -fvisibility=hidden")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-operator-names -DNO_DEPRECATED_OPENSSL")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-attributes -Wno-null-dereference")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-parentheses -Wno-reorder")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-missing-braces -Wno-switch")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-switch-enum -Wno-sign-compare")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-strict-overflow -Wno-unused")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-shorten-64-to-32")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -DNDEBUG")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fexceptions")

# ------------- Source files ----------------------------------------------------

# Core library sources
file(GLOB CORE_SRCS    ${SRC_DIR}/cbmpc/core/*.cpp)
file(GLOB CRYPTO_SRCS  ${SRC_DIR}/cbmpc/crypto/*.cpp)
file(GLOB ZK_SRCS      ${SRC_DIR}/cbmpc/zk/*.cpp)
file(GLOB PROTO_SRCS   ${SRC_DIR}/cbmpc/protocol/*.cpp)
file(GLOB FFI_SRCS     ${SRC_DIR}/cbmpc/ffi/*.cpp)

# CGO binding sources (C API wrappers)
set(CGO_SRCS
  ${CGO_DIR}/ac.cpp
  ${CGO_DIR}/agree_random.cpp
  ${CGO_DIR}/curve.cpp
  ${CGO_DIR}/ecdsa2p.cpp
  ${CGO_DIR}/ecdsamp.cpp
  ${CGO_DIR}/eckeymp.cpp
  ${CGO_DIR}/eddsamp.cpp
  ${CGO_DIR}/network.cpp
  ${CGO_DIR}/pve.cpp
  ${CGO_DIR}/zk.cpp
)

# WASM-specific binding
set(WASM_SRCS ${CMAKE_CURRENT_LIST_DIR}/binding.cpp)

# ------------- Build target ----------------------------------------------------

add_executable(cbmpc_wasm
  ${CORE_SRCS}
  ${CRYPTO_SRCS}
  ${ZK_SRCS}
  ${PROTO_SRCS}
  ${FFI_SRCS}
  ${CGO_SRCS}
  ${WASM_SRCS}
)

target_include_directories(cbmpc_wasm PRIVATE
  ${SRC_DIR}
  ${CGO_DIR}
  ${OPENSSL_INCLUDE}
  ${ROOT_DIR}/vendors
)

target_link_libraries(cbmpc_wasm PRIVATE ${OPENSSL_LIB})

# ------------- Emscripten link flags -------------------------------------------

set_target_properties(cbmpc_wasm PROPERTIES
  OUTPUT_NAME "cbmpc"
  SUFFIX ".js"
)

# Exported C functions (prefixed with _ for Emscripten)
set(EXPORTED_FUNCTIONS
  # Memory
  "_malloc"
  "_free"
  "_wasm_alloc"
  "_wasm_free"
  "_wasm_cmem_data"
  "_wasm_cmem_size"
  "_wasm_cmems_count"
  "_wasm_cmems_get"
  # Curve
  "_new_ecurve"
  "_free_ecurve"
  "_free_ecc_point"
  "_ecurve_generator"
  "_ecurve_order"
  "_ecurve_get_curve_code"
  "_ecurve_random_scalar"
  "_ecurve_mul_generator"
  "_ecc_point_from_bytes"
  "_ecc_point_to_bytes"
  "_ecc_point_multiply"
  "_ecc_point_add"
  "_ecc_point_subtract"
  "_ecc_point_get_x"
  "_ecc_point_get_y"
  "_ecc_point_is_zero"
  "_ecc_point_equals"
  "_ecc_verify_der"
  "_bn_add"
  "_ec_mod_add"
  "_bn_from_int64"
  # Network
  "_wasm_new_job_2p"
  "_free_job_2p"
  "_wasm_new_job_mp"
  "_free_job_mp"
  "_is_peer1"
  "_is_peer2"
  "_get_role_index"
  "_get_party_idx"
  "_get_n_parties"
  "_new_party_set"
  "_party_set_add"
  "_free_party_set"
  # ECDSA 2P
  "_mpc_ecdsa2p_dkg"
  "_mpc_ecdsa2p_refresh"
  "_mpc_ecdsa2p_sign"
  "_free_mpc_ecdsa2p_key"
  "_mpc_ecdsa2p_key_get_role_index"
  "_mpc_ecdsa2p_key_get_Q"
  "_mpc_ecdsa2p_key_get_x_share"
  "_mpc_ecdsa2p_key_get_curve_code"
  # EC Key MP
  "_mpc_eckey_mp_dkg"
  "_mpc_eckey_mp_refresh"
  "_free_mpc_eckey_mp"
  "_mpc_eckey_mp_get_Q"
  "_mpc_eckey_mp_get_curve"
  "_mpc_eckey_mp_get_x_share"
  "_mpc_eckey_mp_get_party_name"
  "_serialize_mpc_eckey_mp"
  "_deserialize_mpc_eckey_mp"
  # ECDSA MP
  "_mpc_ecdsampc_sign"
  # EdDSA MP
  "_mpc_eddsampc_sign"
  # ZK
  "_zk_dl_prove"
  "_zk_dl_verify"
  # Agree random
  "_mpc_agree_random"
)

list(JOIN EXPORTED_FUNCTIONS "," EXPORTED_FUNCTIONS_STR)

# Exported runtime methods for JS interop
set(EXPORTED_RUNTIME_METHODS
  "ccall"
  "cwrap"
  "addFunction"
  "removeFunction"
  "getValue"
  "setValue"
  "UTF8ToString"
  "stringToUTF8"
  "lengthBytesUTF8"
  "HEAPU8"
)
list(JOIN EXPORTED_RUNTIME_METHODS "," EXPORTED_RUNTIME_STR)

target_link_options(cbmpc_wasm PRIVATE
  "SHELL:-s MODULARIZE=1"
  "SHELL:-s EXPORT_NAME='createCbMpc'"
  "SHELL:-s EXPORTED_FUNCTIONS=[${EXPORTED_FUNCTIONS_STR}]"
  "SHELL:-s EXPORTED_RUNTIME_METHODS=[${EXPORTED_RUNTIME_STR}]"
  "SHELL:-s ALLOW_TABLE_GROWTH=1"
  "SHELL:-s ASYNCIFY=1"
  "SHELL:-s ASYNCIFY_STACK_SIZE=65536"
  "SHELL:-s ALLOW_MEMORY_GROWTH=1"
  "SHELL:-s INITIAL_MEMORY=33554432"
  "SHELL:-s MAXIMUM_MEMORY=268435456"
  "SHELL:-s STACK_SIZE=1048576"
  "SHELL:-s NO_EXIT_RUNTIME=1"
  "SHELL:-s FILESYSTEM=0"
  "SHELL:-s ENVIRONMENT='web,node'"
  "SHELL:-s SINGLE_FILE=0"
  "SHELL:-s WASM=1"
)
