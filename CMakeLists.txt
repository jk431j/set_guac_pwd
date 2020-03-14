cmake_minimum_required(VERSION 3.1)
project(set_guac_pwd)
add_library(libmysqlcppconn SHARED IMPORTED)
add_library(libuuid SHARED IMPORTED)

set(CMAKE_CXX_STANDARD 14)

add_executable(set_guac_pwd main.cpp)
target_link_libraries(set_guac_pwd uuid)
target_link_libraries(set_guac_pwd mysqlcppconn)