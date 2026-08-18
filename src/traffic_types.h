#pragma once

#include <compare>
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
};

struct TrafficSnapshot {
    TrafficKey key;
    std::wstring process_name;
    std::uint64_t sent_bytes{};
    std::uint64_t received_bytes{};
    double sent_bytes_per_second{};
    double received_bytes_per_second{};
};
