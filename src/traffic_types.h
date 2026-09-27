#pragma once

#include <array>
#include <chrono>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <string>

enum class TransportProtocol {
    Tcp,
    Udp,
};

enum class TrafficDirection {
    Send,
    Receive,
};

enum class IpAddressFamily {
    V4,
    V6,
};

struct IpAddress {
    IpAddressFamily family;
    std::array<std::byte, 16> bytes;
    auto operator<=>(const IpAddress&) const = default;
};

enum class ApplicationProtocol {
    Ftp,
    Ssh,
    Smtp,
    Dns,
    Dhcp,
    Http,
    Pop3,
    Ntp,
    Imap,
    Ldap,
    HttpsTls,
    Quic,
    Smb,
    IpsecIke,
    SqlServer,
    MySql,
    Rdp,
    PostgreSql,
    Redis,
    MongoDb,
    Other,
};

struct ProcessInstanceId {
    std::uint32_t pid{};
    std::uint64_t creation_time_100ns{};
    auto operator<=>(const ProcessInstanceId&) const = default;
};

struct TrafficKey {
    ProcessInstanceId process;
    TransportProtocol transport{};
    ApplicationProtocol application_protocol{};
    auto operator<=>(const TrafficKey&) const = default;
};

struct TrafficEvent {
    TrafficKey key;
    std::wstring process_name;
    TrafficDirection direction{};
    std::uint64_t bytes{};
    std::chrono::steady_clock::time_point observed_at;
};

struct TrafficSnapshot {
    TrafficKey key;
    std::wstring process_name;
    std::uint64_t sent_bytes{};
    std::uint64_t received_bytes{};
    double sent_bytes_per_second{};
    double received_bytes_per_second{};
};

struct NetworkEndpoint {
    IpAddress address;
    std::uint16_t port{};
    auto operator<=>(const NetworkEndpoint&) const = default;
};

struct ConnectionKey {
    ProcessInstanceId process;
    TransportProtocol transport{};
    ApplicationProtocol application_protocol{};
    NetworkEndpoint local;
    NetworkEndpoint remote;
    auto operator<=>(const ConnectionKey&) const = default;
};

struct ConnectionEvent {
    ConnectionKey key;
    std::wstring process_name;
    TrafficDirection direction{};
    std::uint64_t bytes{};
    std::chrono::steady_clock::time_point observed_at;
};

struct ConnectionSnapshot {
    ConnectionKey key;
    std::wstring process_name;
    std::uint64_t sent_bytes{};
    std::uint64_t received_bytes{};
    double sent_bytes_per_second{};
    double received_bytes_per_second{};
    std::chrono::steady_clock::time_point last_activity;
};
