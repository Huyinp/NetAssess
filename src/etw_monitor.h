#pragma once

#include "etw_decoder.h"
#include "process_info.h"
#include "traffic_aggregator.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>

class IEtwSessionApi {
public:
    virtual ~IEtwSessionApi() = default;

    virtual ULONG StartTraceW(TRACEHANDLE* session_handle, LPCWSTR session_name,
                              EVENT_TRACE_PROPERTIES* properties) = 0;
    virtual TRACEHANDLE OpenTraceW(EVENT_TRACE_LOGFILEW* log_file) = 0;
    virtual ULONG ProcessTrace(TRACEHANDLE* trace_handles, ULONG trace_handle_count,
                               FILETIME* start_time, FILETIME* end_time) = 0;
    virtual ULONG CloseTrace(TRACEHANDLE trace_handle) = 0;
    virtual ULONG ControlTraceW(TRACEHANDLE session_handle, LPCWSTR session_name,
                                EVENT_TRACE_PROPERTIES* properties, ULONG control_code) = 0;
};

class EtwMonitor {
public:
    EtwMonitor(TrafficAggregator& aggregator, ProcessInfoCache& process_cache);
    EtwMonitor(TrafficAggregator& aggregator, ProcessInfoCache& process_cache,
               IEtwSessionApi& session_api);
    ~EtwMonitor();

    EtwMonitor(const EtwMonitor&) = delete;
    EtwMonitor& operator=(const EtwMonitor&) = delete;

    bool Start();
    void Stop();

    bool running() const noexcept;
    std::uint64_t events_lost() const;
    std::uint64_t parse_failures() const noexcept;
    ULONG last_error() const noexcept;

private:
    static void WINAPI EventRecordCallback(EVENT_RECORD* record);

    void Consume(TRACEHANDLE trace_handle);
    void HandleEvent(const EVENT_RECORD& record);
    void CloseOwnedResources();
    void StopOwnedSessionLocked();
    void SetLastErrorIfEmpty(ULONG error) const noexcept;
    EVENT_TRACE_PROPERTIES* properties() noexcept;

    TrafficAggregator& aggregator_;
    ProcessInfoCache& process_cache_;
    IEtwSessionApi& session_api_;
    EtwDecoder decoder_;

    mutable std::mutex lifecycle_mutex_;
    mutable std::mutex api_mutex_;
    std::wstring session_name_;
    std::vector<std::byte> properties_buffer_;
    EVENT_TRACE_LOGFILEW log_file_{};
    TRACEHANDLE session_handle_{};
    TRACEHANDLE trace_handle_{INVALID_PROCESSTRACE_HANDLE};
    std::jthread consumer_;

    std::atomic_bool running_{};
    std::atomic_bool cleanup_started_{};
    mutable std::atomic_uint64_t events_lost_{};
    mutable std::atomic<ULONG> last_error_{};
};
