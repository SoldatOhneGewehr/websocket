cmake_minimum_required(VERSION 3.10)
project(Websocket)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

find_package(Boost REQUIRED COMPONENTS system json)

find_package(Threads REQUIRED)

add_executable(websocket 
    src/main.cpp 
    src/Websocket.cpp
    src/JsonParser.cpp
)

target_include_directories(websocket PRIVATE include)

target_link_libraries(websocket PRIVATE
    Boost::system
    Boost::json
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

target_compile_options(websocket PRIVATE 
    -g
    -O0
    -Wall 
    -Wextra
    -march=native
)
