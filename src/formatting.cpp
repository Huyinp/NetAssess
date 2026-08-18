#include "formatting.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cwctype>
#include <iomanip>
#include <limits>
#include <sstream>

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
    const auto result = std::lexicographical_compare_three_way(
        left.begin(), left.end(), right.begin(), right.end(),
        [](wchar_t left_character, wchar_t right_character) {
            return std::compare_three_way{}(std::towlower(left_character),
                                            std::towlower(right_character));
        });
    return result < 0 ? -1 : result > 0 ? 1 : 0;
}

template <typename T>
int CompareValues(const T& left, const T& right) {
    return left < right ? -1 : left > right ? 1 : 0;
}

int CompareByColumn(const TrafficSnapshot& left, const TrafficSnapshot& right,
                    SortColumn column) {
    switch (column) {
    case SortColumn::ProcessName:
        return CompareCaseInsensitive(left.process_name, right.process_name);
    case SortColumn::Pid:
        return CompareValues(left.key.process.pid, right.key.process.pid);
    case SortColumn::Status:
        return 0;
    case SortColumn::Transport:
        return CompareValues(left.key.transport, right.key.transport);
    case SortColumn::ApplicationProtocol:
        return CompareValues(left.key.application_protocol, right.key.application_protocol);
    case SortColumn::SentBytes:
        return CompareValues(left.sent_bytes, right.sent_bytes);
    case SortColumn::SentRate:
        return CompareValues(ComparableRate(left.sent_bytes_per_second),
                             ComparableRate(right.sent_bytes_per_second));
    case SortColumn::ReceivedBytes:
        return CompareValues(left.received_bytes, right.received_bytes);
    case SortColumn::ReceivedRate:
        return CompareValues(ComparableRate(left.received_bytes_per_second),
                             ComparableRate(right.received_bytes_per_second));
    case SortColumn::CombinedSpeed:
        return CompareValues(CombinedRate(left), CombinedRate(right));
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

void SortTrafficRows(std::vector<TrafficSnapshot>& rows, SortColumn column, bool ascending) {
    std::stable_sort(rows.begin(), rows.end(), [column, ascending](const TrafficSnapshot& left,
                                                                    const TrafficSnapshot& right) {
        const int comparison = CompareByColumn(left, right, column);
        if (comparison != 0) {
            return ascending ? comparison < 0 : comparison > 0;
        }
        return left.key < right.key;
    });
}
