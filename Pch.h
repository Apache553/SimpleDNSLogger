#pragma once


#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/array.hpp>
#include <proto/SimpleDNSLogger.pb.h>
#include <proto/SimpleDNSLogger.grpc.pb.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/alarm.h>
#include <grpcpp/grpcpp.h>

#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <functional>
#include <limits>
#include <vector>
#include <thread>
#include <mutex>
