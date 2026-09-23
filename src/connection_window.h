#pragma once

#include "traffic_types.h"

#include <string>
#include <string_view>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

class ConnectionAggregator;
class ProcessInfoCache;
using ConnectionErrorPresenter = void (*)(HWND, std::wstring_view, DWORD);

inline constexpr UINT kConnectionWindowRefreshMessage = WM_APP + 2;
inline constexpr UINT kConnectionWindowClosedMessage = WM_APP + 3;

struct ConnectionWindowCreationResult {
    HWND window{};
    DWORD error{};
};

ConnectionWindowCreationResult CreateConnectionWindow(
    HINSTANCE instance, HWND owner, ProcessInstanceId process, std::wstring process_name,
    ConnectionAggregator& aggregator, ProcessInfoCache& process_cache,
    ConnectionErrorPresenter error_presenter = nullptr);
