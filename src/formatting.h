#pragma once

#include "traffic_types.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

std::wstring FormatBytes(std::uint64_t bytes);
std::wstring FormatRate(double bytes_per_second);
std::wstring_view ProcessStatusText(bool alive);

enum class SortColumn {
    ProcessName,
    Pid,
    Status,
    Transport,
    ApplicationProtocol,
    SentBytes,
    SentRate,
    ReceivedBytes,
    ReceivedRate,
    CombinedSpeed,
};

void SortTrafficRows(std::vector<TrafficSnapshot>& rows,
                     SortColumn column = SortColumn::CombinedSpeed,
                     bool ascending = false);
