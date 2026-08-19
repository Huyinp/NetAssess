#pragma once

#include "traffic_types.h"

#include <string>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

class ConnectionAggregator;
class ProcessInfoCache;

inline constexpr UINT kConnectionWindowRefreshMessage = WM_APP + 2;

HWND CreateConnectionWindow(HINSTANCE instance, HWND owner, ProcessInstanceId process,
                            std::wstring process_name, ConnectionAggregator& aggregator,
                            ProcessInfoCache& process_cache);
