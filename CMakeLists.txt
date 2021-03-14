cmake_minimum_required (VERSION 3.8)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project("cpphttplib")

find_package(OpenSSL REQUIRED)

file(GLOB_RECURSE cpphttplib_SOURCE
    "include/*"
    "source/*"
)

add_library (cpphttplib SHARED ${cpphttplib_SOURCE})

if (DEFINED LIBRARY_OUTPUT_DIR)
    message( ${LIBRARY_OUTPUT_DIR})
    set_target_properties(cpphttplib PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${LIBRARY_OUTPUT_DIR})
endif()

if (DEFINED RUNTIME_OUTPUT_DIR)
    message( ${RUNTIME_OUTPUT_DIR})
    set_target_properties(cpphttplib PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${RUNTIME_OUTPUT_DIR})
endif()

target_include_directories(cpphttplib PUBLIC ${cpphttplib_SOURCE_DIR}/include)
target_link_libraries(cpphttplib OpenSSL::SSL OpenSSL::Crypto)


target_compile_definitions(cpphttplib PRIVATE CPPHTTPLIBMAKEDLL CPPHTTPLIB_OPENSSL_SUPPORT)