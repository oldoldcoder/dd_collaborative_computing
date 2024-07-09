#cmake_minimum_required(VERSION 3.25)
#project(dd_cComputing CXX)
#
## 指定 C++ 标准
#set(CMAKE_CXX_STANDARD 11)
#set(CMAKE_CXX_STANDARD_REQUIRED True)
## 设置编译选项
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
#
## 强制使用静态链接的 OpenSSL 库
#set(OPENSSL_INCLUDE_DIR "D:\\software\\lib\\OpenSSL\\include")
#set(OPENSSL_CRYPTO_LIBRARY "D:\\software\\lib\\OpenSSL\\lib\\vc\\x64\\MT\\libcrypto_static.lib")
#set(OPENSSL_SSL_LIBRARY "D:\\software\\lib\\OpenSSL\\lib\\vc\\x64\\MT\\libssl_static.lib")
#
#aux_source_directory(include SOURCE_FILES)
#aux_source_directory(test SOURCE_FILES)
#include_directories(include ${OPENSSL_INCLUDE_DIR})
#
#add_executable(${PROJECT_NAME} ${SOURCE_FILES})
#add_executable(main ${SOURCE_FILES})
#target_include_directories(${PROJECT_NAME} PUBLIC include)
#target_include_directories(main PUBLIC include)
## 链接 OpenSSL 库
#target_link_libraries(${PROJECT_NAME}  ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY} ws2_32 Crypt32)
#target_link_libraries(main ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY} ws2_32 Crypt32)


cmake_minimum_required(VERSION 3.25)
project(dd_cComputing CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")

# 强制使用静态链接的 OpenSSL 库
set(OPENSSL_INCLUDE_DIR "D:\\software\\lib\\OpenSSL\\include")
set(OPENSSL_CRYPTO_LIBRARY "D:\\software\\lib\\OpenSSL\\lib\\vc\\x64\\MT\\libcrypto_static.lib")
set(OPENSSL_SSL_LIBRARY "D:\\software\\lib\\OpenSSL\\lib\\vc\\x64\\MT\\libssl_static.lib")

aux_source_directory(include SOURCE_FILES)
include_directories(include ${OPENSSL_INCLUDE_DIR})


# 编译为动态链接库（DLL）
add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES})
set_target_properties(${PROJECT_NAME} PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)
# 链接 OpenSSL 和 eTPSS 库
target_link_libraries(${PROJECT_NAME}  ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY} ws2_32 Crypt32)
