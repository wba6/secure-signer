cmake_minimum_required(VERSION 3.20)
project(secure_signer)

set(CMAKE_CXX_STANDARD 17)

add_executable(secure_signer main.cpp RSAClient.cpp RSAClient.hpp User.cpp User.hpp)
