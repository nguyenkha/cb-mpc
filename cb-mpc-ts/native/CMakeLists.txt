cmake_minimum_required(VERSION 3.16)

project(cbmpc_native LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ------------- Paths -----------------------------------------------------------

set(ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../..)
set(SRC_DIR ${ROOT_DIR}/src)
set(CGO_DIR ${ROOT_DIR}/demos-go/cb-mpc-go/internal/cgobinding)
set(TS_DIR ${CMAKE_CURRENT_LIST_DIR}/..)

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
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fexceptions")

# ------------- Source files ----------------------------------------------------

file(GLOB CORE_SRCS    ${SRC_DIR}/cbmpc/core/*.cpp)
file(GLOB CRYPTO_SRCS  ${SRC_DIR}/cbmpc/crypto/*.cpp)
file(GLOB ZK_SRCS      ${SRC_DIR}/cbmpc/zk/*.cpp)
file(GLOB PROTO_SRCS   ${SRC_DIR}/cbmpc/protocol/*.cpp)
file(GLOB FFI_SRCS     ${SRC_DIR}/cbmpc/ffi/*.cpp)

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
  ${CGO_DIR}/schnorr2p.cpp
  ${CGO_DIR}/zk.cpp
)

set(BINDING_SRCS ${TS_DIR}/binding.cpp)

# ------------- Build target ----------------------------------------------------

add_library(cbmpc SHARED
  ${CORE_SRCS}
  ${CRYPTO_SRCS}
  ${ZK_SRCS}
  ${PROTO_SRCS}
  ${FFI_SRCS}
  ${CGO_SRCS}
  ${BINDING_SRCS}
)

target_include_directories(cbmpc PRIVATE
  ${SRC_DIR}
  ${CGO_DIR}
  ${ROOT_DIR}/vendors
)

link_openssl(cbmpc)

# Set output name and platform-specific settings
if(IS_MACOS)
  set_target_properties(cbmpc PROPERTIES
    OUTPUT_NAME "cbmpc"
    SUFFIX ".dylib"
    INSTALL_RPATH "@loader_path"
  )
elseif(IS_LINUX)
  set_target_properties(cbmpc PROPERTIES
    OUTPUT_NAME "cbmpc"
    SUFFIX ".so"
    INSTALL_RPATH "$ORIGIN"
  )
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

add_custom_command(TARGET cbmpc POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E make_directory "${PREBUILD_DIR}/${INSTALL_PLATFORM}"
  COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:cbmpc>" "${PREBUILD_DIR}/${INSTALL_PLATFORM}/"
  COMMENT "Copying shared library to prebuilds/${INSTALL_PLATFORM}/"
)
