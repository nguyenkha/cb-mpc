cmake_minimum_required(VERSION 3.16)

project(cbmpc_native LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ------------- Paths -----------------------------------------------------------

set(ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../..)
set(SRC_DIR ${ROOT_DIR}/src)
set(TS_DIR ${CMAKE_CURRENT_LIST_DIR}/..)
set(CAPI_DIR ${TS_DIR}/capi)
set(CAPI_SRCS ${CAPI_DIR}/cbmpc_ts.cpp)

include(${ROOT_DIR}/cmake/macros.cmake)
include(${ROOT_DIR}/cmake/arch.cmake)
include(${ROOT_DIR}/cmake/openssl.cmake)

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
# Same as upstream cmake/compilation_flags.cmake: the core uses ARMv8 crypto
# intrinsics (e.g. vmull_p64). Apple clang enables them by default; GCC/clang
# on Linux need it explicitly.
if(IS_ARM64 AND NOT IS_MACOS)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=armv8-a+crypto")
endif()
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fexceptions")

# ------------- Source files ----------------------------------------------------

file(GLOB CORE_SRCS    ${SRC_DIR}/cbmpc/core/*.cpp)
file(GLOB CRYPTO_SRCS  ${SRC_DIR}/cbmpc/crypto/*.cpp)
file(GLOB ZK_SRCS      ${SRC_DIR}/cbmpc/zk/*.cpp)
file(GLOB PROTO_SRCS   ${SRC_DIR}/cbmpc/protocol/*.cpp)


set(BINDING_SRCS ${TS_DIR}/binding.cpp)

# Public API used by the PVE and access-structure bindings
set(API_SRCS
  ${SRC_DIR}/cbmpc/api/pve_base_pke.cpp
  ${SRC_DIR}/cbmpc/api/pve_batch_single_recipient.cpp
  ${SRC_DIR}/cbmpc/api/ecdsa_mp.cpp
  ${SRC_DIR}/cbmpc/api/eddsa_mp.cpp
)

# ------------- Build target ----------------------------------------------------

add_library(cbmpc SHARED
  ${CORE_SRCS}
  ${CRYPTO_SRCS}
  ${ZK_SRCS}
  ${PROTO_SRCS}
  ${API_SRCS}
  ${CAPI_SRCS}
  ${BINDING_SRCS}
)

target_include_directories(cbmpc PRIVATE
  ${ROOT_DIR}/include
  ${ROOT_DIR}/include-internal
  ${SRC_DIR}
  ${CAPI_DIR}
  ${ROOT_DIR}/vendors
)

# Make C ABI symbols visible (they lack __attribute__((visibility("default"))))
set_source_files_properties(${CAPI_SRCS} PROPERTIES
  COMPILE_FLAGS "-fvisibility=default"
)

link_openssl(cbmpc)

# Export list — make C ABI symbols visible despite -fvisibility=hidden
set(EXPORTS_FILE "${CMAKE_CURRENT_LIST_DIR}/exports.txt")
# Relink when the export list changes (the linker reads it, CMake does not track it).
set_property(TARGET cbmpc APPEND PROPERTY LINK_DEPENDS "${EXPORTS_FILE}")

# Set output name and platform-specific settings
if(IS_MACOS)
  set_target_properties(cbmpc PROPERTIES
    OUTPUT_NAME "cbmpc"
    SUFFIX ".dylib"
    INSTALL_RPATH "@loader_path"
  )
  target_link_options(cbmpc PRIVATE "-Wl,-exported_symbols_list,${EXPORTS_FILE}")
elseif(IS_LINUX)
  # Generate a linker version script from the exports list
  file(STRINGS "${EXPORTS_FILE}" _export_lines)
  set(_version_script "{ global:\n")
  foreach(_line ${_export_lines})
    string(STRIP "${_line}" _line)
    if(_line AND NOT _line MATCHES "^#")
      # Remove leading underscore for ELF (no underscore prefix on Linux)
      string(REGEX REPLACE "^_" "" _sym "${_line}")
      string(APPEND _version_script "  ${_sym};\n")
    endif()
  endforeach()
  string(APPEND _version_script "  local: *;\n};\n")
  file(WRITE "${CMAKE_BINARY_DIR}/exports.map" "${_version_script}")

  set_target_properties(cbmpc PROPERTIES
    OUTPUT_NAME "cbmpc"
    SUFFIX ".so"
    INSTALL_RPATH "$ORIGIN"
  )
  target_link_options(cbmpc PRIVATE "-Wl,--version-script=${CMAKE_BINARY_DIR}/exports.map")
  # Link the C++ runtime statically: the .so then needs only glibc (no GLIBCXX
  # version), and the version script above keeps those symbols local.
  target_link_options(cbmpc PRIVATE -static-libstdc++ -static-libgcc)
endif()

# Install to cb-mpc-ts/prebuilds/<platform>-<arch>/
set(PREBUILD_DIR "${TS_DIR}/prebuilds")

if(IS_MACOS AND IS_ARM64)
  set(INSTALL_PLATFORM "darwin-arm64")
elseif(IS_MACOS AND IS_X86_64)
  set(INSTALL_PLATFORM "darwin-x64")
elseif(IS_LINUX AND IS_X86_64)
  set(INSTALL_PLATFORM "linux-x64")
elseif(IS_LINUX AND IS_ARM64)
  set(INSTALL_PLATFORM "linux-arm64")
else()
  set(INSTALL_PLATFORM "unknown")
endif()

# e.g. "-musl" for the Alpine build (prebuilds/linux-x64-musl/)
set(CBMPC_PREBUILD_SUFFIX "" CACHE STRING "Suffix for the prebuilds/<platform> directory")
set(INSTALL_PLATFORM "${INSTALL_PLATFORM}${CBMPC_PREBUILD_SUFFIX}")

add_custom_command(TARGET cbmpc POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E make_directory "${PREBUILD_DIR}/${INSTALL_PLATFORM}"
  COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:cbmpc>" "${PREBUILD_DIR}/${INSTALL_PLATFORM}/"
  COMMENT "Copying shared library to prebuilds/${INSTALL_PLATFORM}/"
)
