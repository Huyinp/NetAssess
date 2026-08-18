#include "etw_monitor.h"

#include "protocol_classifier.h"

#include <cstring>
#include <iterator>
#include <system_error>

#include <objbase.h>

namespace {

class WindowsEtwSessionApi final : public IEtwSessionApi {
public:
    ULONG StartTraceW(TRACEHANDLE* session_handle, LPCWSTR session_name,
                      EVENT_TRACE_PROPERTIES* properties) override {
        return ::StartTraceW(session_handle, session_name, properties);
    }

    TRACEHANDLE OpenTraceW(EVENT_TRACE_LOGFILEW* log_file) override {
        return ::OpenTraceW(log_file);
    }

    ULONG ProcessTrace(TRACEHANDLE* trace_handles, ULONG trace_handle_count,
                       FILETIME* start_time, FILETIME* end_time) override {
        return ::ProcessTrace(trace_handles, trace_handle_count, start_time, end_time);
    }

    ULONG CloseTrace(TRACEHANDLE trace_handle) override {
        return ::CloseTrace(trace_handle);
    }

    ULONG ControlTraceW(TRACEHANDLE session_handle, LPCWSTR session_name,
                        EVENT_TRACE_PROPERTIES* properties, ULONG control_code) override {
        return ::ControlTraceW(session_handle, session_name, properties, control_code);
    }
};

IEtwSessionApi& DefaultSessionApi() {
    static WindowsEtwSessionApi api;
    return api;
}

ULONG HResultToWin32(HRESULT result) {
    return HRESULT_FACILITY(result) == FACILITY_WIN32 ? HRESULT_CODE(result)
                                                       : ERROR_GEN_FAILURE;
}

bool IsIgnorableCloseResult(ULONG result) {
    return result == ERROR_SUCCESS || result == ERROR_CTX_CLOSE_PENDING;
}

bool IsCompletedStopResult(ULONG result) {
    return result == ERROR_SUCCESS || result == ERROR_MORE_DATA ||
           result == ERROR_WMI_INSTANCE_NOT_FOUND || result == ERROR_ACTIVE_CONNECTIONS;
}

}  // namespace

EtwMonitor::EtwMonitor(TrafficAggregator& aggregator, ProcessInfoCache& process_cache)
    : EtwMonitor(aggregator, process_cache, DefaultSessionApi()) {}

EtwMonitor::EtwMonitor(TrafficAggregator& aggregator, ProcessInfoCache& process_cache,
                       IEtwSessionApi& session_api)
    : aggregator_(aggregator), process_cache_(process_cache), session_api_(session_api) {}

EtwMonitor::~EtwMonitor() {
    Stop();
}

bool EtwMonitor::Start() {
    std::lock_guard lock(lifecycle_mutex_);
    if (running_.load(std::memory_order_acquire)) {
        return true;
    }

    StopOwnedSessionLocked();
    last_error_.store(ERROR_SUCCESS, std::memory_order_relaxed);
    events_lost_.store(0, std::memory_order_relaxed);

    GUID session_guid{};
    const HRESULT guid_result = CoCreateGuid(&session_guid);
    if (FAILED(guid_result)) {
        last_error_.store(HResultToWin32(guid_result), std::memory_order_relaxed);
        return false;
    }

    wchar_t guid_text[39]{};
    if (StringFromGUID2(session_guid, guid_text, static_cast<int>(std::size(guid_text))) == 0) {
        last_error_.store(ERROR_INSUFFICIENT_BUFFER, std::memory_order_relaxed);
        return false;
    }
    session_name_ = L"NetAssess-" + std::to_wstring(GetCurrentProcessId()) + L"-" + guid_text;

    const std::size_t properties_size =
        sizeof(EVENT_TRACE_PROPERTIES) + (session_name_.size() + 1) * sizeof(wchar_t);
    properties_buffer_.assign(properties_size, std::byte{});
    auto* trace_properties = properties();
    trace_properties->Wnode.BufferSize = static_cast<ULONG>(properties_size);
    trace_properties->Wnode.Guid = session_guid;
    trace_properties->Wnode.ClientContext = 1;
    trace_properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    trace_properties->LogFileMode =
        EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    trace_properties->EnableFlags = EVENT_TRACE_FLAG_NETWORK_TCPIP;
    trace_properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    std::memcpy(properties_buffer_.data() + trace_properties->LoggerNameOffset,
                session_name_.c_str(), (session_name_.size() + 1) * sizeof(wchar_t));

    const ULONG start_result =
        session_api_.StartTraceW(&session_handle_, session_name_.c_str(), trace_properties);
    if (start_result != ERROR_SUCCESS) {
        last_error_.store(start_result, std::memory_order_relaxed);
        session_handle_ = 0;
        session_name_.clear();
        properties_buffer_.clear();
        return false;
    }

    log_file_ = {};
    log_file_.LoggerName = session_name_.data();
    log_file_.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log_file_.EventRecordCallback = EventRecordCallback;
    log_file_.Context = this;
    trace_handle_ = session_api_.OpenTraceW(&log_file_);
    if (trace_handle_ == INVALID_PROCESSTRACE_HANDLE) {
        ULONG open_error = GetLastError();
        if (open_error == ERROR_SUCCESS) {
            open_error = ERROR_GEN_FAILURE;
        }
        last_error_.store(open_error, std::memory_order_relaxed);
        StopOwnedSessionLocked();
        return false;
    }

    running_.store(true, std::memory_order_release);
    try {
        const TRACEHANDLE trace_handle = trace_handle_;
        consumer_ = std::jthread([this, trace_handle] { Consume(trace_handle); });
    } catch (const std::system_error& error) {
        running_.store(false, std::memory_order_release);
        const ULONG thread_error = static_cast<ULONG>(error.code().value());
        last_error_.store(thread_error == ERROR_SUCCESS ? ERROR_NOT_ENOUGH_MEMORY : thread_error,
                          std::memory_order_relaxed);
        StopOwnedSessionLocked();
        return false;
    }
    return true;
}

void EtwMonitor::Stop() {
    running_.store(false, std::memory_order_release);
    std::lock_guard lock(lifecycle_mutex_);
    StopOwnedSessionLocked();
}

bool EtwMonitor::running() const noexcept {
    return running_.load(std::memory_order_acquire);
}

std::uint64_t EtwMonitor::events_lost() const {
    std::lock_guard lifecycle_lock(lifecycle_mutex_);
    if (session_handle_ == 0 || cleanup_started_.load(std::memory_order_acquire)) {
        return events_lost_.load(std::memory_order_relaxed);
    }

    std::lock_guard api_lock(api_mutex_);
    if (cleanup_started_.load(std::memory_order_acquire)) {
        return events_lost_.load(std::memory_order_relaxed);
    }

    auto query_buffer = properties_buffer_;
    auto* query_properties =
        reinterpret_cast<EVENT_TRACE_PROPERTIES*>(query_buffer.data());
    const ULONG result = session_api_.ControlTraceW(
        session_handle_, session_name_.c_str(), query_properties, EVENT_TRACE_CONTROL_QUERY);
    if (result != ERROR_SUCCESS) {
        SetLastErrorIfEmpty(result);
        return events_lost_.load(std::memory_order_relaxed);
    }

    const auto loss_count = static_cast<std::uint64_t>(query_properties->EventsLost) +
                            static_cast<std::uint64_t>(query_properties->RealTimeBuffersLost);
    events_lost_.store(loss_count, std::memory_order_relaxed);
    return loss_count;
}

std::uint64_t EtwMonitor::parse_failures() const noexcept {
    return decoder_.parse_failures();
}

ULONG EtwMonitor::last_error() const noexcept {
    return last_error_.load(std::memory_order_relaxed);
}

void WINAPI EtwMonitor::EventRecordCallback(EVENT_RECORD* record) {
    if (record == nullptr || record->UserContext == nullptr) {
        return;
    }
    static_cast<EtwMonitor*>(record->UserContext)->HandleEvent(*record);
}

void EtwMonitor::Consume(TRACEHANDLE trace_handle) {
    const ULONG result = session_api_.ProcessTrace(&trace_handle, 1, nullptr, nullptr);
    const bool stopped_unexpectedly = running_.exchange(false, std::memory_order_acq_rel);
    if (stopped_unexpectedly) {
        if (result != ERROR_SUCCESS) {
            SetLastErrorIfEmpty(result);
        }
        bool expected = false;
        if (cleanup_started_.compare_exchange_strong(expected, true,
                                                     std::memory_order_acq_rel)) {
            CloseOwnedResources();
        }
    }
}

void EtwMonitor::HandleEvent(const EVENT_RECORD& record) {
    const auto decoded = decoder_.Decode(record);
    if (!decoded) {
        return;
    }

    const auto process = process_cache_.Resolve(
        decoded->pid, static_cast<std::uint64_t>(record.EventHeader.TimeStamp.QuadPart));
    const auto application_protocol = InferApplicationProtocol(
        decoded->transport, decoded->direction, decoded->source_port,
        decoded->destination_port);
    aggregator_.Add({{process.id, decoded->transport, application_protocol}, process.name,
                     decoded->direction, decoded->bytes});
}

void EtwMonitor::CloseOwnedResources() {
    std::lock_guard api_lock(api_mutex_);
    if (session_handle_ != 0) {
        const ULONG result = session_api_.ControlTraceW(
            session_handle_, session_name_.c_str(), properties(), EVENT_TRACE_CONTROL_STOP);
        if (!IsCompletedStopResult(result)) {
            SetLastErrorIfEmpty(result);
        }
    }

    if (trace_handle_ != INVALID_PROCESSTRACE_HANDLE) {
        const ULONG result = session_api_.CloseTrace(trace_handle_);
        if (!IsIgnorableCloseResult(result)) {
            SetLastErrorIfEmpty(result);
        }
    }
}

void EtwMonitor::StopOwnedSessionLocked() {
    bool expected = false;
    if ((session_handle_ != 0 || trace_handle_ != INVALID_PROCESSTRACE_HANDLE) &&
        cleanup_started_.compare_exchange_strong(expected, true,
                                                 std::memory_order_acq_rel)) {
        CloseOwnedResources();
    }

    if (consumer_.joinable()) {
        if (consumer_.get_id() == std::this_thread::get_id()) {
            return;
        }
        consumer_.join();
    }

    session_handle_ = 0;
    trace_handle_ = INVALID_PROCESSTRACE_HANDLE;
    log_file_ = {};
    session_name_.clear();
    properties_buffer_.clear();
    cleanup_started_.store(false, std::memory_order_release);
}

void EtwMonitor::SetLastErrorIfEmpty(ULONG error) const noexcept {
    ULONG expected = ERROR_SUCCESS;
    last_error_.compare_exchange_strong(expected, error, std::memory_order_relaxed);
}

EVENT_TRACE_PROPERTIES* EtwMonitor::properties() noexcept {
    return reinterpret_cast<EVENT_TRACE_PROPERTIES*>(properties_buffer_.data());
}
