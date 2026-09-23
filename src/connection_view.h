#pragma once

#include "traffic_types.h"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

enum class ConnectionActivityStatus {
    Active,
    Historical,
    ProcessEnded,
};

enum class ConnectionDirection {
    SendOnly,
    ReceiveOnly,
    Bidirectional,
};

struct ConnectionDisplayRow {
    ConnectionSnapshot connection;
    bool process_alive{};
    ConnectionActivityStatus status{};
    ConnectionDirection direction{};
};

struct ConnectionFilter {
    std::wstring ip;
    std::optional<std::uint16_t> port;
};

struct PortFilterParseResult {
    std::optional<std::uint16_t> port;
    bool valid{};
};

enum class ConnectionSortColumn {
    Status,
    Direction,
    Transport,
    ApplicationProtocol,
    LocalAddress,
    LocalPort,
    RemoteAddress,
    RemotePort,
    SentBytes,
    SentRate,
    ReceivedBytes,
    ReceivedRate,
    CombinedSpeed,
};

std::wstring FormatIpAddress(const IpAddress& address);
PortFilterParseResult ParsePortFilter(std::wstring_view text);
std::vector<ConnectionDisplayRow> FilterConnectionRows(std::vector<ConnectionDisplayRow> rows,
                                                        const ConnectionFilter& filter);
std::wstring_view ConnectionActivityStatusText(ConnectionActivityStatus status);
std::wstring_view ConnectionDirectionName(ConnectionDirection direction);

std::vector<ConnectionDisplayRow> BuildConnectionRows(
    const std::vector<ConnectionSnapshot>& snapshots, bool process_alive,
    std::chrono::steady_clock::time_point now,
    ConnectionSortColumn sort_column = ConnectionSortColumn::CombinedSpeed,
    bool ascending = false);
void SortConnectionRows(std::vector<ConnectionDisplayRow>& rows,
                        ConnectionSortColumn column, bool ascending);
std::vector<std::wstring> ConnectionCsvCells(const ConnectionDisplayRow& row);
