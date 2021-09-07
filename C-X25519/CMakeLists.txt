cmake_minimum_required(VERSION 3.0.0)
project(X25519 VERSION 0.1.0)

# Include libsodium
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake/modules")
find_package(sodium REQUIRED)

include_directories(include)
file(GLOB SOURCES "src/*.c")

set(LIBRARY_OUTPUT_PATH "lib")

add_library(project STATIC ${SOURCES})
target_link_libraries(project sodium)

set_target_properties(project PROPERTIES OUTPUT_NAME "X25519")

include(CTest)
enable_testing()

#add_library(X25519 X25519.cpp)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)

