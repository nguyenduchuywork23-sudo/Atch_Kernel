# CMake generated Testfile for 
# Source directory: C:/Users/Nguye/OneDrive/Desktop/Atch_Kernel/tests
# Build directory: C:/Users/Nguye/OneDrive/Desktop/Atch_Kernel/build/tests
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test([=[basic_test]=] "C:/Users/Nguye/OneDrive/Desktop/Atch_Kernel/build/tests/Debug/basic_test.exe")
  set_tests_properties([=[basic_test]=] PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/Nguye/OneDrive/Desktop/Atch_Kernel/tests/CMakeLists.txt;13;add_test;C:/Users/Nguye/OneDrive/Desktop/Atch_Kernel/tests/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test([=[basic_test]=] "C:/Users/Nguye/OneDrive/Desktop/Atch_Kernel/build/tests/Release/basic_test.exe")
  set_tests_properties([=[basic_test]=] PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/Nguye/OneDrive/Desktop/Atch_Kernel/tests/CMakeLists.txt;13;add_test;C:/Users/Nguye/OneDrive/Desktop/Atch_Kernel/tests/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test([=[basic_test]=] "C:/Users/Nguye/OneDrive/Desktop/Atch_Kernel/build/tests/MinSizeRel/basic_test.exe")
  set_tests_properties([=[basic_test]=] PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/Nguye/OneDrive/Desktop/Atch_Kernel/tests/CMakeLists.txt;13;add_test;C:/Users/Nguye/OneDrive/Desktop/Atch_Kernel/tests/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test([=[basic_test]=] "C:/Users/Nguye/OneDrive/Desktop/Atch_Kernel/build/tests/RelWithDebInfo/basic_test.exe")
  set_tests_properties([=[basic_test]=] PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/Nguye/OneDrive/Desktop/Atch_Kernel/tests/CMakeLists.txt;13;add_test;C:/Users/Nguye/OneDrive/Desktop/Atch_Kernel/tests/CMakeLists.txt;0;")
else()
  add_test([=[basic_test]=] NOT_AVAILABLE)
endif()
