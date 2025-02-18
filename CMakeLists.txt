cmake_minimum_required(VERSION 3.16)
project(secure_signer)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ----------------------------------------------------------------------
# Locate GMP
#
# Users can override these by passing -DGMP_INCLUDE_DIR or -DGMP_LIBRARY
# or by setting the corresponding environment variables.
# ----------------------------------------------------------------------

# Define common search hints for GMP include directories
set(GMP_INCLUDE_HINTS
  /usr/include
  /usr/local/include
  /usr/include/x86_64-linux-gnu
  /opt/local/include
  $ENV{GMP_INCLUDE_DIR}
)

# Try to locate gmp.h using our hints; first try a limited search (NO_DEFAULT_PATH)
find_path(GMP_INCLUDE_DIR
  NAMES gmp.h
  HINTS ${GMP_INCLUDE_HINTS}
  NO_DEFAULT_PATH
)

# If not found, perform a full search using the hints
if(NOT GMP_INCLUDE_DIR)
  find_path(GMP_INCLUDE_DIR
    NAMES gmp.h
    HINTS ${GMP_INCLUDE_HINTS}
  )
endif()

if(NOT GMP_INCLUDE_DIR)
  message(FATAL_ERROR "Could not find GMP header (gmp.h). Please install GMP or set -DGMP_INCLUDE_DIR=<path>.")
else()
  message(STATUS "Found GMP include directory: ${GMP_INCLUDE_DIR}")
endif()

# Define common search hints for GMP library directories
set(GMP_LIBRARY_HINTS
  /usr/lib
  /usr/local/lib
  /usr/lib/x86_64-linux-gnu
  /opt/local/lib
  $ENV{GMP_LIBRARY}
)

# Try to locate the GMP library; first with a limited search
find_library(GMP_LIBRARY
  NAMES gmp
  HINTS ${GMP_LIBRARY_HINTS}
  NO_DEFAULT_PATH
)

# If not found, perform a full search using the hints
if(NOT GMP_LIBRARY)
  find_library(GMP_LIBRARY
    NAMES gmp
    HINTS ${GMP_LIBRARY_HINTS}
  )
endif()

if(NOT GMP_LIBRARY)
  message(FATAL_ERROR "Could not find GMP library. Please install GMP or set -DGMP_LIBRARY=<path>.")
else()
  message(STATUS "Found GMP library: ${GMP_LIBRARY}")
endif()


include_directories(${GMP_INCLUDE_DIR} ${PROJECT_SOURCE_DIR}/vendor)

add_executable(secure_signer
  main.cpp
  RSAClient.cpp
  RSAClient.hpp
)

# Link the executable with the GMP library
target_link_libraries(secure_signer ${GMP_LIBRARY})
