cmake_minimum_required (VERSION 3.8)
project("SimpleDNSLogger")

find_package(Protobuf REQUIRED)
find_package(gRPC CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS system)

file(GLOB PROTO_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/proto/*.proto
)

set(SOURCE_FILES
    "Main.cpp"
 "DnsServer.cpp")

set(HEADER_FILES
 "Main.h" "Rpc.h" "DnsServer.h")

add_executable (SimpleDNSLogger ${SOURCE_FILES} ${HEADER_FILES} ${PROTO_FILES})
target_compile_features(SimpleDNSLogger PRIVATE cxx_std_17)
target_include_directories(SimpleDNSLogger PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(SimpleDNSLogger
    PUBLIC
        protobuf::libprotobuf
        gRPC::grpc
        gRPC::grpc++
        Boost::system
)


get_target_property(grpc_cpp_plugin_location gRPC::grpc_cpp_plugin LOCATION)
protobuf_generate(TARGET SimpleDNSLogger LANGUAGE cpp)
protobuf_generate(TARGET SimpleDNSLogger LANGUAGE grpc GENERATE_EXTENSIONS .grpc.pb.h .grpc.pb.cc PLUGIN "protoc-gen-grpc=${grpc_cpp_plugin_location}")


