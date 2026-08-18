#pragma once

#include "formatting.h"

#include <functional>
#include <string_view>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

class EtwMonitor;
class ProcessInfoCache;
class TrafficAggregator;

std::vector<TrafficDisplayRow> BuildVisibleRows(
    const std::vector<TrafficSnapshot>& snapshots, std::wstring_view filter,
    SortColumn sort_column, bool ascending,
    const std::function<bool(ProcessInstanceId)>& alive_lookup);

HWND CreateMainWindow(HINSTANCE instance, TrafficAggregator& aggregator,
                      ProcessInfoCache& process_cache, EtwMonitor& monitor);
bool StartMainWindowCollection(HWND window);
