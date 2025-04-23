cmake_minimum_required (VERSION 3.16)

project(net-test CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(dnspacket
	"source/main.cpp"
	"source/dns.cpp")

target_include_directories(dnspacket PUBLIC
	"3rd_party/asio/asio/include"
	"."
)

target_precompile_headers(dnspacket PUBLIC "source/pch.hpp")

if(WIN32)
	target_link_libraries(dnspacket ws2_32)
endif()

add_definitions(-DASIO_STANDALONE)
