cmake_minimum_required(VERSION 3.24)
project(Atch_Kernel_Tests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)

# We create a simple basic test for now. 
# This test is a ring 3 user-mode application that simulates interactions
# or tests driver interfaces (Ping/Pong IOCTL, etc.)

add_executable(basic_test basic_test.cpp)

# A simple CTest
add_test(NAME basic_test COMMAND basic_test)
