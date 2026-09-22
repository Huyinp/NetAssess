#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <unordered_map>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <sdkddkver.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

struct NetworkInterfaceCounters {
    std::uint64_t interface_luid;
    IF_OPER_STATUS status;
    NET_IFTYPE type;
    std::uint64_t in_octets;
    std::uint64_t out_octets;
};

struct NetworkRateSnapshot {
    double received_bytes_per_second;
    double sent_bytes_per_second;
    DWORD error;
};

class INetworkInterfaceApi {
public:
    virtual ~INetworkInterfaceApi() = default;
    virtual DWORD Query(std::vector<NetworkInterfaceCounters>& rows) = 0;
};

class NetworkRateMonitor {
public:
    NetworkRateMonitor();
    explicit NetworkRateMonitor(INetworkInterfaceApi& api);

    NetworkRateSnapshot Snapshot(std::chrono::steady_clock::time_point now);

private:
    struct Baseline {
        std::uint64_t in_octets;
        std::uint64_t out_octets;
        std::chrono::steady_clock::time_point time;
    };

    std::unique_ptr<INetworkInterfaceApi> owned_api_;
    INetworkInterfaceApi& api_;
    std::unordered_map<std::uint64_t, Baseline> baselines_;
};
