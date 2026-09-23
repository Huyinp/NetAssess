#pragma once

#include "formatting.h"

#include <chrono>
#include <functional>
#include <map>
#include <optional>
#include <span>
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
class ConnectionAggregator;
class ProcessInfoCache;
class TrafficAggregator;
class ProcessActions;
class NetworkRateMonitor;
struct CsvSaveResult;

struct MainWindowDependencies {
    ProcessActions* process_actions{};
    NetworkRateMonitor* network_rate_monitor{};
    int (*choose_menu_command)(HWND, HMENU, POINT){};
    bool (*confirm_termination)(HWND, std::wstring_view, ProcessInstanceId){};
    void (*present_error)(HWND, std::wstring_view, DWORD){};
    CsvSaveResult (*save_csv)(HWND, std::wstring_view,
                              std::span<const std::wstring>,
                              std::span<const std::vector<std::wstring>>){};
    std::chrono::steady_clock::time_point (*sample_time)(){};
};

std::vector<TrafficDisplayRow> BuildVisibleRows(
    const std::vector<TrafficSnapshot>& snapshots, std::wstring_view filter,
    SortColumn sort_column, bool ascending,
    const std::function<bool(ProcessInstanceId)>& alive_lookup);
std::optional<ProcessInstanceId> ProcessForVisibleRow(
    std::span<const TrafficKey> current_keys, int row);
bool EraseConnectionWindowIfMatches(
    std::map<ProcessInstanceId, HWND>& registry, HWND window);
std::map<ProcessInstanceId, HWND> TakeConnectionWindows(
    std::map<ProcessInstanceId, HWND>& registry);

HWND CreateMainWindow(HINSTANCE instance, TrafficAggregator& aggregator,
                      ConnectionAggregator& connection_aggregator,
                      ProcessInfoCache& process_cache, EtwMonitor& monitor);
HWND CreateMainWindow(HINSTANCE instance, TrafficAggregator& aggregator,
                      ConnectionAggregator& connection_aggregator,
                      ProcessInfoCache& process_cache, EtwMonitor& monitor,
                      MainWindowDependencies dependencies);
bool StartMainWindowCollection(HWND window);
