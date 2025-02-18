cmake_minimum_required(VERSION 3.20)
project(secure_signer)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Look for the GMP header (gmp.h)
find_path(GMP_INCLUDE_DIR NAMES gmp.h)
if(NOT GMP_INCLUDE_DIR)
  message(FATAL_ERROR "Could not find GMP header directory (gmp.h)")
endif()

# Look for the GMP library (usually named libgmp.so, libgmp.a, or gmp.lib)
find_library(GMP_LIBRARY NAMES gmp)
if(NOT GMP_LIBRARY)
  message(FATAL_ERROR "Could not find GMP library")
endif()

include_directories(${PROJECT_SOURCE_DIR}/vendor/)
add_executable(secure_signer main.cpp RSAClient.cpp RSAClient.hpp)

# Link your executable with the GMP library
target_link_libraries(secure_signer ${GMP_LIBRARY})
