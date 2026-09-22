#include "connection_view.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>
#include <utility>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

namespace {

constexpr auto kActiveWindow = std::chrono::seconds(5);

double ComparableRate(double value) {
    return std::isfinite(value) && value >= 0.0 ? value : 0.0;
}

double CombinedRate(const ConnectionSnapshot& snapshot) {
    const double combined = ComparableRate(snapshot.sent_bytes_per_second) +
                            ComparableRate(snapshot.received_bytes_per_second);
    return std::isfinite(combined) ? combined : std::numeric_limits<double>::max();
}

template <typename T>
int CompareValues(const T& left, const T& right) {
    return left < right ? -1 : left > right ? 1 : 0;
}

int CompareByColumn(const ConnectionDisplayRow& left, const ConnectionDisplayRow& right,
                    ConnectionSortColumn column) {
    const ConnectionSnapshot& left_connection = left.connection;
    const ConnectionSnapshot& right_connection = right.connection;
    switch (column) {
    case ConnectionSortColumn::Status:
        return CompareValues(left.status, right.status);
    case ConnectionSortColumn::Direction:
        return CompareValues(left.direction, right.direction);
    case ConnectionSortColumn::Transport:
        return CompareValues(left_connection.key.transport, right_connection.key.transport);
    case ConnectionSortColumn::ApplicationProtocol:
        return CompareValues(left_connection.key.application_protocol,
                             right_connection.key.application_protocol);
    case ConnectionSortColumn::LocalAddress:
        return CompareValues(left_connection.key.local.address, right_connection.key.local.address);
    case ConnectionSortColumn::LocalPort:
        return CompareValues(left_connection.key.local.port, right_connection.key.local.port);
    case ConnectionSortColumn::RemoteAddress:
        return CompareValues(left_connection.key.remote.address,
                             right_connection.key.remote.address);
    case ConnectionSortColumn::RemotePort:
        return CompareValues(left_connection.key.remote.port, right_connection.key.remote.port);
    case ConnectionSortColumn::SentBytes:
        return CompareValues(left_connection.sent_bytes, right_connection.sent_bytes);
    case ConnectionSortColumn::SentRate:
        return CompareValues(ComparableRate(left_connection.sent_bytes_per_second),
                             ComparableRate(right_connection.sent_bytes_per_second));
    case ConnectionSortColumn::ReceivedBytes:
        return CompareValues(left_connection.received_bytes, right_connection.received_bytes);
    case ConnectionSortColumn::ReceivedRate:
        return CompareValues(ComparableRate(left_connection.received_bytes_per_second),
                             ComparableRate(right_connection.received_bytes_per_second));
    case ConnectionSortColumn::CombinedSpeed:
        return CompareValues(CombinedRate(left_connection), CombinedRate(right_connection));
    }
    return 0;
}

bool ContainsInvariantCaseInsensitive(std::wstring_view value, std::wstring_view needle) {
    if (needle.empty()) {
        return true;
    }
    if (needle.size() > value.size()) {
        return false;
    }
    for (std::size_t offset = 0; offset + needle.size() <= value.size(); ++offset) {
        if (CompareStringOrdinal(value.data() + offset, static_cast<int>(needle.size()),
                                 needle.data(), static_cast<int>(needle.size()), TRUE) ==
            CSTR_EQUAL) {
            return true;
        }
    }
    return false;
}

bool MatchesConnectionFilter(const ConnectionDisplayRow& row, const ConnectionFilter& filter) {
    const ConnectionKey& key = row.connection.key;
    const bool ip_matches =
        ContainsInvariantCaseInsensitive(FormatIpAddress(key.local.address), filter.ip) ||
        ContainsInvariantCaseInsensitive(FormatIpAddress(key.remote.address), filter.ip);
    const bool port_matches = !filter.port.has_value() || key.local.port == *filter.port ||
                              key.remote.port == *filter.port;
    return ip_matches && port_matches;
}

}  // namespace

std::wstring FormatIpAddress(const IpAddress& address) {
    wchar_t buffer[INET6_ADDRSTRLEN]{};
    if (address.family == IpAddressFamily::V4) {
        IN_ADDR ipv4{};
        std::memcpy(&ipv4, address.bytes.data(), sizeof(ipv4));
        if (InetNtopW(AF_INET, &ipv4, buffer, static_cast<DWORD>(std::size(buffer))) != nullptr) {
            return buffer;
        }
    } else {
        IN6_ADDR ipv6{};
        std::memcpy(&ipv6, address.bytes.data(), sizeof(ipv6));
        if (InetNtopW(AF_INET6, &ipv6, buffer, static_cast<DWORD>(std::size(buffer))) != nullptr) {
            return buffer;
        }
    }
    return L"无效地址";
}

PortFilterParseResult ParsePortFilter(std::wstring_view text) {
    if (text.empty()) {
        return {std::nullopt, true};
    }

    std::uint32_t value = 0;
    for (const wchar_t character : text) {
        if (character < L'0' || character > L'9') {
            return {std::nullopt, false};
        }
        const std::uint32_t digit = static_cast<std::uint32_t>(character - L'0');
        if (value > (std::numeric_limits<std::uint16_t>::max() - digit) / 10) {
            return {std::nullopt, false};
        }
        value = value * 10 + digit;
    }
    return {static_cast<std::uint16_t>(value), true};
}

std::vector<ConnectionDisplayRow> FilterConnectionRows(std::vector<ConnectionDisplayRow> rows,
                                                        const ConnectionFilter& filter) {
    std::vector<ConnectionDisplayRow> filtered;
    filtered.reserve(rows.size());
    for (ConnectionDisplayRow& row : rows) {
        if (MatchesConnectionFilter(row, filter)) {
            filtered.push_back(std::move(row));
        }
    }
    return filtered;
}

std::wstring_view ConnectionActivityStatusText(ConnectionActivityStatus status) {
    switch (status) {
    case ConnectionActivityStatus::Active:
        return L"活跃";
    case ConnectionActivityStatus::Historical:
        return L"历史";
    case ConnectionActivityStatus::ProcessEnded:
        return L"进程已结束";
    }
    return L"历史";
}

std::wstring_view ConnectionDirectionName(ConnectionDirection direction) {
    switch (direction) {
    case ConnectionDirection::SendOnly:
        return L"上行";
    case ConnectionDirection::ReceiveOnly:
        return L"下行";
    case ConnectionDirection::Bidirectional:
        return L"双向";
    }
    return L"双向";
}

std::vector<ConnectionDisplayRow> BuildConnectionRows(
    const std::vector<ConnectionSnapshot>& snapshots, bool process_alive,
    std::chrono::steady_clock::time_point now, ConnectionSortColumn sort_column, bool ascending) {
    std::vector<ConnectionDisplayRow> rows;
    rows.reserve(snapshots.size());
    for (const ConnectionSnapshot& snapshot : snapshots) {
        const ConnectionActivityStatus status =
            !process_alive ? ConnectionActivityStatus::ProcessEnded
                           : now - snapshot.last_activity <= kActiveWindow
                                 ? ConnectionActivityStatus::Active
                                 : ConnectionActivityStatus::Historical;
        const ConnectionDirection direction =
            snapshot.sent_bytes == 0 ? ConnectionDirection::ReceiveOnly
                                     : snapshot.received_bytes == 0
                                           ? ConnectionDirection::SendOnly
                                           : ConnectionDirection::Bidirectional;
        rows.push_back({snapshot, process_alive, status, direction});
    }
    SortConnectionRows(rows, sort_column, ascending);
    return rows;
}

void SortConnectionRows(std::vector<ConnectionDisplayRow>& rows, ConnectionSortColumn column,
                        bool ascending) {
    std::stable_sort(rows.begin(), rows.end(), [column, ascending](const ConnectionDisplayRow& left,
                                                                    const ConnectionDisplayRow& right) {
        const int comparison = CompareByColumn(left, right, column);
        if (comparison != 0) {
            return ascending ? comparison < 0 : comparison > 0;
        }
        return left.connection.key < right.connection.key;
    });
}
