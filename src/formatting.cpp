#include "formatting.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <iomanip>
#include <limits>
#include <sstream>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

namespace {

constexpr double kUnitDivisor = 1024.0;
constexpr std::array<std::wstring_view, 5> kUnits{L"B", L"KB", L"MB", L"GB", L"TB"};

std::wstring FormatScaled(double value, std::wstring_view suffix) {
    std::size_t unit_index = 0;
    while (value >= kUnitDivisor && unit_index + 1 < kUnits.size()) {
        value /= kUnitDivisor;
        ++unit_index;
    }

    std::wostringstream stream;
    stream << std::fixed << std::setprecision(2) << value;
    std::wstring number = stream.str();
    number.erase(number.find_last_not_of(L'0') + 1);
    if (!number.empty() && number.back() == L'.') {
        number.pop_back();
    }
    return number + L" " + std::wstring{kUnits[unit_index]} + std::wstring{suffix};
}

double ComparableRate(double value) {
    return std::isfinite(value) && value >= 0.0 ? value : 0.0;
}

double CombinedRate(const TrafficSnapshot& snapshot) {
    const double combined = ComparableRate(snapshot.sent_bytes_per_second) +
                            ComparableRate(snapshot.received_bytes_per_second);
    return std::isfinite(combined) ? combined : std::numeric_limits<double>::max();
}

int CompareCaseInsensitive(std::wstring_view left, std::wstring_view right) {
    const int result = CompareStringOrdinal(
        left.data(), static_cast<int>(left.size()), right.data(),
        static_cast<int>(right.size()), TRUE);
    return result == CSTR_LESS_THAN ? -1 : result == CSTR_GREATER_THAN ? 1 : 0;
}

template <typename T>
int CompareValues(const T& left, const T& right) {
    return left < right ? -1 : left > right ? 1 : 0;
}

int CompareByColumn(const TrafficDisplayRow& left, const TrafficDisplayRow& right,
                    SortColumn column) {
    const TrafficSnapshot& left_traffic = left.traffic;
    const TrafficSnapshot& right_traffic = right.traffic;
    switch (column) {
    case SortColumn::ProcessName:
        return CompareCaseInsensitive(left_traffic.process_name, right_traffic.process_name);
    case SortColumn::Pid:
        return CompareValues(left_traffic.key.process.pid, right_traffic.key.process.pid);
    case SortColumn::Status:
        return CompareValues(left.process_alive, right.process_alive);
    case SortColumn::Transport:
        return CompareValues(left_traffic.key.transport, right_traffic.key.transport);
    case SortColumn::ApplicationProtocol:
        return CompareValues(left_traffic.key.application_protocol,
                             right_traffic.key.application_protocol);
    case SortColumn::SentBytes:
        return CompareValues(left_traffic.sent_bytes, right_traffic.sent_bytes);
    case SortColumn::SentRate:
        return CompareValues(ComparableRate(left_traffic.sent_bytes_per_second),
                             ComparableRate(right_traffic.sent_bytes_per_second));
    case SortColumn::ReceivedBytes:
        return CompareValues(left_traffic.received_bytes, right_traffic.received_bytes);
    case SortColumn::ReceivedRate:
        return CompareValues(ComparableRate(left_traffic.received_bytes_per_second),
                             ComparableRate(right_traffic.received_bytes_per_second));
    case SortColumn::CombinedSpeed:
        return CompareValues(CombinedRate(left_traffic), CombinedRate(right_traffic));
    }
    return 0;
}

}  // namespace

std::wstring FormatBytes(std::uint64_t bytes) {
    return FormatScaled(static_cast<double>(bytes), L"");
}

std::wstring FormatRate(double bytes_per_second) {
    return FormatScaled(ComparableRate(bytes_per_second), L"/s");
}

std::wstring_view ProcessStatusText(bool alive) {
    return alive ? L"运行中" : L"已结束";
}

std::wstring_view TransportProtocolName(TransportProtocol protocol) {
    return protocol == TransportProtocol::Tcp ? L"TCP" : L"UDP";
}

void SortTrafficRows(std::vector<TrafficDisplayRow>& rows, SortColumn column, bool ascending) {
    std::stable_sort(rows.begin(), rows.end(), [column, ascending](const TrafficDisplayRow& left,
                                                                    const TrafficDisplayRow& right) {
        const int comparison = CompareByColumn(left, right, column);
        if (comparison != 0) {
            return ascending ? comparison < 0 : comparison > 0;
        }
        return left.traffic.key < right.traffic.key;
    });
}
