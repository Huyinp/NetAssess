#include "etw_decoder.h"
#include "etw_monitor.h"
#include "connection_aggregator.h"
#include "connection_view.h"
#include "connection_window.h"
#include "csv_export.h"
#include "formatting.h"
#include "main_window.h"
#include "process_info.h"
#include "process_actions.h"
#include "protocol_classifier.h"
#include "single_instance.h"
#include "traffic_aggregator.h"
#include "win32_dpi.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <functional>
#include <initializer_list>
#include <iostream>
#include <limits>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#define NOMINMAX
#include <windows.h>
#include <tdh.h>
#include <commctrl.h>

#include "list_view_state.h"

namespace {

int failures = 0;

template <typename T>
void PrintValue(std::ostream& stream, const T& value) {
    stream << value;
}

void PrintValue(std::ostream& stream, ApplicationProtocol value) {
    stream << static_cast<int>(value);
}

void PrintValue(std::ostream& stream, ConnectionActivityStatus value) {
    stream << static_cast<int>(value);
}

void PrintValue(std::ostream& stream, ConnectionDirection value) {
    stream << static_cast<int>(value);
}

void PrintValue(std::ostream& stream, const ConnectionKey& value) {
    stream << value.process.pid;
}

void PrintValue(std::ostream& stream, std::wstring_view value) {
    for (const wchar_t character : value) {
        stream << (character < 128 ? static_cast<char>(character) : '?');
    }
}

void PrintValue(std::ostream& stream, const std::wstring& value) {
    PrintValue(stream, std::wstring_view{value});
}

void PrintValue(std::ostream& stream, const wchar_t* value) {
    PrintValue(stream, std::wstring_view{value});
}

const TrafficSnapshot& FindSnapshot(const std::vector<TrafficSnapshot>& snapshots,
                                    const TrafficKey& key) {
    const auto snapshot = std::find_if(snapshots.begin(), snapshots.end(),
                                       [&key](const TrafficSnapshot& value) {
                                           return value.key == key;
                                       });
    if (snapshot == snapshots.end()) {
        std::cerr << __FILE__ << ':' << __LINE__ << ": missing traffic snapshot" << std::endl;
        ++failures;
        static const TrafficSnapshot missing{};
        return missing;
    }
    return *snapshot;
}

const ConnectionSnapshot& FindConnectionSnapshot(
    const std::vector<ConnectionSnapshot>& snapshots, const ConnectionKey& key) {
    const auto snapshot = std::find_if(snapshots.begin(), snapshots.end(),
                                       [&key](const ConnectionSnapshot& value) {
                                           return value.key == key;
                                       });
    if (snapshot == snapshots.end()) {
        std::cerr << __FILE__ << ':' << __LINE__ << ": missing connection snapshot" << std::endl;
        ++failures;
        static const ConnectionSnapshot missing{};
        return missing;
    }
    return *snapshot;
}

IpAddress MakeIpv4Address(std::uint8_t first, std::uint8_t second, std::uint8_t third,
                          std::uint8_t fourth) {
    IpAddress address{IpAddressFamily::V4, {}};
    address.bytes[0] = static_cast<std::byte>(first);
    address.bytes[1] = static_cast<std::byte>(second);
    address.bytes[2] = static_cast<std::byte>(third);
    address.bytes[3] = static_cast<std::byte>(fourth);
    return address;
}

IpAddress MakeIpv6Address(std::initializer_list<std::uint8_t> bytes) {
    IpAddress address{IpAddressFamily::V6, {}};
    std::size_t index{};
    for (const std::uint8_t value : bytes) {
        address.bytes[index++] = static_cast<std::byte>(value);
    }
    return address;
}

ConnectionKey MakeConnectionKey(ProcessInstanceId process, TransportProtocol transport,
                                ApplicationProtocol application_protocol, std::uint16_t local_port,
                                std::uint16_t remote_port, IpAddress local = MakeIpv4Address(10, 0, 0, 1),
                                IpAddress remote = MakeIpv4Address(8, 8, 8, 8)) {
    return {process, transport, application_protocol, {local, local_port}, {remote, remote_port}};
}

class FakeEtwSessionApi final : public IEtwSessionApi {
public:
    ULONG StartTraceW(TRACEHANDLE* session_handle, LPCWSTR session_name,
                      EVENT_TRACE_PROPERTIES* properties) override {
        std::lock_guard lock(mutex);
        ++start_trace_calls;
        started_name = session_name;
        properties_guid = properties->Wnode.Guid;
        properties_flags = properties->Wnode.Flags;
        client_context = properties->Wnode.ClientContext;
        log_file_mode = properties->LogFileMode;
        enable_flags = properties->EnableFlags;
        calls.emplace_back("start");
        close_requested = false;
        query_started = false;
        allow_query = false;
        stop_started = false;
        allow_stop = false;
        worker_action_ready = false;
        allow_worker_action = false;
        worker_action_finished = false;
        worker_action_threw = false;
        const ULONG result = start_status_index < start_statuses.size()
                                 ? start_statuses[start_status_index++] : start_status;
        if (result == ERROR_SUCCESS) {
            *session_handle = session_handle_to_return;
        }
        return result;
    }

    TRACEHANDLE OpenTraceW(EVENT_TRACE_LOGFILEW* log_file) override {
        std::lock_guard lock(mutex);
        ++open_trace_calls;
        opened_name = log_file->LoggerName;
        open_mode = log_file->ProcessTraceMode;
        opened_context = log_file->Context;
        has_event_callback = log_file->EventRecordCallback != nullptr;
        event_callback = log_file->EventRecordCallback;
        calls.emplace_back("open");
        if (trace_handle_to_return == INVALID_PROCESSTRACE_HANDLE) {
            SetLastError(open_error);
        }
        return trace_handle_to_return;
    }

    ULONG ProcessTrace(TRACEHANDLE*, ULONG, FILETIME*, FILETIME*) override {
        std::function<void()> action;
        {
            std::lock_guard lock(mutex);
            ++process_trace_calls;
            calls.emplace_back("process");
            action = process_trace_action;
            condition.notify_all();
        }

        if (action) {
            {
                std::unique_lock lock(mutex);
                worker_action_ready = true;
                condition.notify_all();
                if (hold_worker_action) {
                    condition.wait(lock, [this] { return allow_worker_action; });
                }
            }
            bool threw = false;
            try {
                action();
            } catch (...) {
                threw = true;
            }
            std::lock_guard lock(mutex);
            worker_action_threw = threw;
            worker_action_finished = true;
            condition.notify_all();
        }

        std::unique_lock lock(mutex);
        if (block_process_trace) {
            condition.wait_for(lock, std::chrono::seconds(2),
                               [this] { return close_requested; });
        }
        return process_status;
    }

    ULONG CloseTrace(TRACEHANDLE trace_handle) override {
        std::lock_guard lock(mutex);
        ++close_trace_calls;
        closed_trace_handle = trace_handle;
        calls.emplace_back("close");
        close_requested = true;
        condition.notify_all();
        return close_status;
    }

    ULONG ControlTraceW(TRACEHANDLE session_handle, LPCWSTR session_name,
                        EVENT_TRACE_PROPERTIES* properties, ULONG control_code) override {
        std::unique_lock lock(mutex);
        if (control_code == EVENT_TRACE_CONTROL_QUERY) {
            ++control_query_calls;
            queried_session_handle = session_handle;
            queried_name = session_name;
            calls.emplace_back("control-query");
            query_started = true;
            condition.notify_all();
            if (block_query) {
                condition.wait(lock, [this] { return allow_query; });
            }
            properties->EventsLost = query_events_lost;
            properties->RealTimeBuffersLost = query_real_time_buffers_lost;
            return query_status;
        }

        ++control_stop_calls;
        controlled_session_handle = session_handle;
        controlled_name = session_name;
        stopped_names.emplace_back(session_name == nullptr ? L"" : session_name);
        controlled_code = control_code;
        calls.emplace_back("control-stop");
        properties->EventsLost = stop_events_lost;
        properties->RealTimeBuffersLost = stop_real_time_buffers_lost;
        stop_started = true;
        condition.notify_all();
        if (block_stop) {
            condition.wait(lock, [this] { return allow_stop; });
        }
        if (control_stop_index < control_stop_statuses.size()) {
            return control_stop_statuses[control_stop_index++];
        }
        return control_status;
    }

    ULONG QueryAllTracesW(EVENT_TRACE_PROPERTIES** property_array,
                          ULONG property_array_count, PULONG logger_count) override {
        ++query_all_calls;
        *logger_count = static_cast<ULONG>(active_session_names.size());
        if (property_array_count < active_session_names.size()) {
            return ERROR_MORE_DATA;
        }
        for (std::size_t index = 0; index < active_session_names.size(); ++index) {
            auto* properties = property_array[index];
            auto* name = reinterpret_cast<wchar_t*>(
                reinterpret_cast<std::byte*>(properties) + properties->LoggerNameOffset);
            const std::size_t capacity =
                (properties->Wnode.BufferSize - properties->LoggerNameOffset) / sizeof(wchar_t);
            wcsncpy_s(name, capacity, active_session_names[index].c_str(), _TRUNCATE);
        }
        return query_all_status;
    }

    bool WaitForConsumers(int expected = 1) {
        std::unique_lock lock(mutex);
        return condition.wait_for(lock, std::chrono::seconds(2),
                                  [this, expected] { return process_trace_calls >= expected; });
    }

    bool WaitForClose() {
        return WaitForCloseFor(std::chrono::seconds(2));
    }

    bool WaitForCloseFor(std::chrono::milliseconds timeout) {
        std::unique_lock lock(mutex);
        return condition.wait_for(lock, timeout,
                                  [this] { return close_requested; });
    }

    bool WaitForQuery() {
        std::unique_lock lock(mutex);
        return condition.wait_for(lock, std::chrono::seconds(2),
                                  [this] { return query_started; });
    }

    void ReleaseQuery() {
        std::lock_guard lock(mutex);
        allow_query = true;
        condition.notify_all();
    }

    bool WaitForStop() {
        std::unique_lock lock(mutex);
        return condition.wait_for(lock, std::chrono::seconds(2),
                                  [this] { return stop_started; });
    }

    void ReleaseStop() {
        std::lock_guard lock(mutex);
        allow_stop = true;
        condition.notify_all();
    }

    bool WaitForWorkerAction() {
        std::unique_lock lock(mutex);
        return condition.wait_for(lock, std::chrono::seconds(2),
                                  [this] { return worker_action_finished; });
    }

    bool WaitForWorkerActionReady() {
        std::unique_lock lock(mutex);
        return condition.wait_for(lock, std::chrono::seconds(2),
                                  [this] { return worker_action_ready; });
    }

    void ReleaseWorkerAction() {
        std::lock_guard lock(mutex);
        allow_worker_action = true;
        condition.notify_all();
    }

    bool WorkerActionThrew() {
        std::lock_guard lock(mutex);
        return worker_action_threw;
    }

    int StopCallCount() {
        std::lock_guard lock(mutex);
        return control_stop_calls;
    }

    void SetProcessTraceAction(std::function<void()> action) {
        std::lock_guard lock(mutex);
        process_trace_action = std::move(action);
    }

    void InvokeEventCallback(EVENT_RECORD& record) {
        record.UserContext = opened_context;
        event_callback(&record);
    }

    void HoldProcessTraceAction(bool hold) {
        std::lock_guard lock(mutex);
        hold_worker_action = hold;
    }

    ULONG start_status{ERROR_SUCCESS};
    std::vector<ULONG> start_statuses;
    std::size_t start_status_index{};
    ULONG query_all_status{ERROR_SUCCESS};
    ULONG query_status{ERROR_SUCCESS};
    ULONG open_error{ERROR_INVALID_HANDLE};
    ULONG process_status{ERROR_CANCELLED};
    ULONG close_status{ERROR_SUCCESS};
    ULONG control_status{ERROR_SUCCESS};
    TRACEHANDLE session_handle_to_return{101};
    TRACEHANDLE trace_handle_to_return{202};
    ULONG query_events_lost{};
    ULONG query_real_time_buffers_lost{};
    ULONG stop_events_lost{};
    ULONG stop_real_time_buffers_lost{};
    std::vector<ULONG> control_stop_statuses;
    std::size_t control_stop_index{};
    bool block_process_trace{true};
    bool block_query{};
    bool block_stop{};

    int start_trace_calls{};
    int open_trace_calls{};
    int process_trace_calls{};
    int close_trace_calls{};
    int control_query_calls{};
    int control_stop_calls{};
    int query_all_calls{};
    std::wstring started_name;
    std::wstring opened_name;
    std::wstring controlled_name;
    std::wstring queried_name;
    GUID properties_guid{};
    ULONG properties_flags{};
    ULONG client_context{};
    ULONG log_file_mode{};
    ULONG enable_flags{};
    ULONG open_mode{};
    void* opened_context{};
    bool has_event_callback{};
    PEVENT_RECORD_CALLBACK event_callback{};
    TRACEHANDLE closed_trace_handle{};
    TRACEHANDLE controlled_session_handle{};
    TRACEHANDLE queried_session_handle{};
    ULONG controlled_code{};
    std::vector<std::string> calls;
    std::vector<std::wstring> active_session_names;
    std::vector<std::wstring> stopped_names;

private:
    std::mutex mutex;
    std::condition_variable condition;
    std::function<void()> process_trace_action;
    bool close_requested{};
    bool query_started{};
    bool allow_query{};
    bool stop_started{};
    bool allow_stop{};
    bool hold_worker_action{};
    bool worker_action_ready{};
    bool allow_worker_action{};
    bool worker_action_finished{};
    bool worker_action_threw{};
};

class FakeProcessInfoApi final : public IProcessInfoApi {
public:
    std::optional<ProcessInfo> QueryProcess(std::uint32_t) override {
        ++query_process_calls;
        if (query_index < query_results.size()) {
            return query_results[query_index++];
        }
        return std::nullopt;
    }

    std::optional<std::uint64_t> QueryCreationTime(std::uint32_t) override {
        ++query_creation_time_calls;
        if (creation_time_index < creation_time_results.size()) {
            return creation_time_results[creation_time_index++];
        }
        return creation_time;
    }

    std::vector<std::optional<ProcessInfo>> query_results;
    std::size_t query_index{};
    std::optional<std::uint64_t> creation_time;
    std::vector<std::optional<std::uint64_t>> creation_time_results;
    std::size_t creation_time_index{};
    int query_process_calls{};
    int query_creation_time_calls{};
};

class FakeProcessActionApi final : public IProcessActionApi {
public:
    HANDLE OpenProcess(DWORD desired_access, BOOL inherit_handle, DWORD process_id) override {
        calls.push_back(L"open");
        ++open_process_calls;
        requested_access = desired_access;
        opened_inherit_handle = inherit_handle;
        opened_process_id = process_id;
        return open_succeeds ? process_handle : nullptr;
    }

    BOOL GetProcessTimes(HANDLE handle, FILETIME* creation_time, FILETIME*, FILETIME*,
                         FILETIME*) override {
        calls.push_back(L"times");
        ++get_process_times_calls;
        timed_handle = handle;
        if (!get_process_times_succeeds) {
            return FALSE;
        }
        creation_time->dwLowDateTime = static_cast<DWORD>(creation_time_100ns);
        creation_time->dwHighDateTime =
            static_cast<DWORD>(creation_time_100ns >> 32);
        return TRUE;
    }

    BOOL QueryFullProcessImageNameW(HANDLE handle, DWORD flags, LPWSTR path,
                                    PDWORD path_length) override {
        calls.push_back(L"path");
        ++query_image_path_calls;
        queried_path_handle = handle;
        queried_path_flags = flags;
        if (!query_image_path_succeeds) {
            return FALSE;
        }
        if (*path_length < image_path.size()) {
            last_error = ERROR_INSUFFICIENT_BUFFER;
            return FALSE;
        }
        std::copy(image_path.begin(), image_path.end(), path);
        *path_length = static_cast<DWORD>(image_path.size());
        return TRUE;
    }

    BOOL ShellExecuteExW(SHELLEXECUTEINFOW* execute_info) override {
        calls.push_back(L"shell");
        ++shell_execute_calls;
        shell_file = execute_info->lpFile == nullptr ? L"" : execute_info->lpFile;
        shell_parameters =
            execute_info->lpParameters == nullptr ? L"" : execute_info->lpParameters;
        shell_mask = execute_info->fMask;
        shell_show = execute_info->nShow;
        return shell_execute_succeeds ? TRUE : FALSE;
    }

    BOOL TerminateProcess(HANDLE handle, UINT exit_code) override {
        calls.push_back(L"terminate");
        ++terminate_process_calls;
        terminated_handle = handle;
        terminate_exit_code = exit_code;
        return terminate_process_succeeds ? TRUE : FALSE;
    }

    BOOL CloseHandle(HANDLE handle) override {
        calls.push_back(L"close");
        ++close_handle_calls;
        closed_handle = handle;
        return TRUE;
    }

    DWORD LastError() const override { return last_error; }

    HANDLE process_handle = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(0x9876));
    bool open_succeeds{true};
    bool get_process_times_succeeds{true};
    bool query_image_path_succeeds{true};
    bool shell_execute_succeeds{true};
    bool terminate_process_succeeds{true};
    DWORD last_error{ERROR_ACCESS_DENIED};
    std::uint64_t creation_time_100ns{77};
    std::wstring image_path{L"C:\\Program Files\\tools,here\\app.exe"};
    int open_process_calls{};
    int get_process_times_calls{};
    int query_image_path_calls{};
    int shell_execute_calls{};
    int terminate_process_calls{};
    int close_handle_calls{};
    DWORD requested_access{};
    BOOL opened_inherit_handle{};
    DWORD opened_process_id{};
    HANDLE timed_handle{};
    HANDLE queried_path_handle{};
    DWORD queried_path_flags{};
    HANDLE terminated_handle{};
    UINT terminate_exit_code{};
    HANDLE closed_handle{};
    std::wstring shell_file;
    std::wstring shell_parameters;
    ULONG shell_mask{};
    int shell_show{};
    std::vector<std::wstring> calls;
};

int RunEtwMonitorStopInterleavingChild() {
    TrafficAggregator aggregator;
    ConnectionAggregator connection_aggregator;
    ProcessInfoCache process_cache;
    FakeEtwSessionApi api;
    EtwMonitor monitor(aggregator, connection_aggregator, process_cache, api);
    api.HoldProcessTraceAction(true);
    api.SetProcessTraceAction([&] { monitor.Stop(); });

    if (!monitor.Start() || !api.WaitForWorkerActionReady()) {
        return 10;
    }

    std::atomic_bool external_stop_returned{};
    std::jthread external_stop([&] {
        monitor.Stop();
        external_stop_returned.store(true, std::memory_order_release);
    });
    if (!api.WaitForClose() || external_stop_returned.load(std::memory_order_acquire)) {
        ExitProcess(11);
    }

    api.ReleaseWorkerAction();
    if (!api.WaitForWorkerAction()) {
        ExitProcess(12);
    }
    external_stop.join();
    if (!external_stop_returned.load(std::memory_order_acquire) ||
        api.control_stop_calls != 1 || api.close_trace_calls != 1) {
        return 13;
    }

    monitor.Stop();
    return api.control_stop_calls == 1 && api.close_trace_calls == 1 ? 0 : 14;
}

DWORD RunEtwMonitorStopInterleavingProcess() {
    std::wstring executable(MAX_PATH, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, executable.data(),
                                            static_cast<DWORD>(executable.size()));
    if (length == 0 || length == executable.size()) {
        return GetLastError();
    }
    executable.resize(length);

    std::wstring command_line = L"\"" + executable + L"\" --etw-stop-interleaving-child";
    std::vector<wchar_t> command_buffer(command_line.begin(), command_line.end());
    command_buffer.push_back(L'\0');
    STARTUPINFOW startup{sizeof(startup)};
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(nullptr, command_buffer.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) {
        return GetLastError();
    }

    const DWORD wait_result = WaitForSingleObject(process.hProcess, 5000);
    DWORD exit_code = ERROR_TIMEOUT;
    if (wait_result == WAIT_OBJECT_0) {
        GetExitCodeProcess(process.hProcess, &exit_code);
    } else {
        TerminateProcess(process.hProcess, ERROR_TIMEOUT);
        WaitForSingleObject(process.hProcess, INFINITE);
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return exit_code;
}

#define CHECK_EQ(actual, expected)                                                   \
    do {                                                                             \
        const auto actual_value = (actual);                                          \
        const auto expected_value = (expected);                                      \
        if (actual_value != expected_value) {                                        \
            std::cerr << __FILE__ << ':' << __LINE__ << ": actual=";                \
            PrintValue(std::cerr, actual_value);                                     \
            std::cerr << ", expected=";                                             \
            PrintValue(std::cerr, expected_value);                                   \
            std::cerr << std::endl;                                                  \
            ++failures;                                                               \
        }                                                                            \
    } while (false)

EventLayout MakeIpv4Layout(TrafficDirection direction, TransportProtocol transport) {
    EventLayout layout{};
    layout.pid = {0, 4};
    layout.size = {4, 4};
    layout.destination_address = {8, 4};
    layout.source_address = {12, 4};
    layout.destination_port = {16, 2};
    layout.source_port = {18, 2};
    layout.direction = direction;
    layout.transport = transport;
    layout.address_family = IpAddressFamily::V4;
    return layout;
}

struct SchemaProperty {
    const wchar_t* name;
    USHORT in_type;
    USHORT length{};
    PROPERTY_FLAGS flags{};
};

class SchemaFixture final {
public:
    explicit SchemaFixture(std::initializer_list<SchemaProperty> properties) {
        auto* information = reinterpret_cast<TRACE_EVENT_INFO*>(buffer_.data());
        information->PropertyCount = static_cast<ULONG>(properties.size());
        information->TopLevelPropertyCount = static_cast<ULONG>(properties.size());

        std::size_t name_offset = offsetof(TRACE_EVENT_INFO, EventPropertyInfoArray) +
                                  properties.size() * sizeof(EVENT_PROPERTY_INFO);
        std::size_t index = 0;
        for (const auto& definition : properties) {
            auto& property = information->EventPropertyInfoArray[index++];
            property.Flags = definition.flags;
            property.nonStructType.InType = definition.in_type;
            property.length = definition.length;
            property.count = 1;
            property.NameOffset = static_cast<ULONG>(name_offset);

            const std::size_t name_size = std::wcslen(definition.name) + 1;
            std::memcpy(buffer_.data() + name_offset, definition.name,
                        name_size * sizeof(wchar_t));
            name_offset += name_size * sizeof(wchar_t);
        }
        size_ = name_offset;
    }

    std::span<const std::byte> bytes() const { return {buffer_.data(), size_}; }

private:
    alignas(TRACE_EVENT_INFO) std::array<std::byte, 1024> buffer_{};
    std::size_t size_{};
};

EVENT_RECORD MakeNetworkRecord(const GUID& provider, std::uint8_t opcode) {
    EVENT_RECORD record{};
    record.EventHeader.ProviderId = provider;
    record.EventHeader.EventDescriptor.Opcode = opcode;
    record.EventHeader.Flags = EVENT_HEADER_FLAG_64_BIT_HEADER;
    return record;
}

constexpr GUID kTestTcpIpProvider{0x9a280ac0, 0xc8e0, 0x11d1,
                                  {0x84, 0xe2, 0x00, 0xc0, 0x4f, 0xb9, 0x98, 0xa2}};
constexpr GUID kTestUdpIpProvider{0xbf3a50c5, 0xa9c9, 0x4988,
                                  {0xa0, 0x05, 0x2d, 0xf0, 0xb7, 0xc8, 0x0f, 0x80}};

void TestTrafficAggregationKeepsDistinctKeysAndDirectionsSeparate() {
    TrafficAggregator aggregator;
    const auto t0 = std::chrono::steady_clock::time_point{};
    const TrafficKey first{{100, 1}, TransportProtocol::Tcp, ApplicationProtocol::HttpsTls};
    const TrafficKey different_pid{{101, 1}, TransportProtocol::Tcp,
                                   ApplicationProtocol::HttpsTls};
    const TrafficKey different_creation_time{{100, 2}, TransportProtocol::Tcp,
                                             ApplicationProtocol::HttpsTls};
    const TrafficKey different_transport_and_protocol{{100, 1}, TransportProtocol::Udp,
                                                       ApplicationProtocol::Quic};

    aggregator.Add({first, L"first.exe", TrafficDirection::Send, 100});
    aggregator.Add({different_pid, L"pid.exe", TrafficDirection::Receive, 200});
    aggregator.Add({different_creation_time, L"created.exe", TrafficDirection::Send, 300});
    aggregator.Add({different_transport_and_protocol, L"udp.exe", TrafficDirection::Receive,
                    400});

    const auto snapshots = aggregator.Snapshot(t0);
    CHECK_EQ(snapshots.size(), 4U);
    CHECK_EQ(FindSnapshot(snapshots, first).sent_bytes, 100ULL);
    CHECK_EQ(FindSnapshot(snapshots, first).received_bytes, 0ULL);
    CHECK_EQ(FindSnapshot(snapshots, different_pid).sent_bytes, 0ULL);
    CHECK_EQ(FindSnapshot(snapshots, different_pid).received_bytes, 200ULL);
    CHECK_EQ(FindSnapshot(snapshots, different_creation_time).sent_bytes, 300ULL);
    CHECK_EQ(FindSnapshot(snapshots, different_creation_time).received_bytes, 0ULL);
    CHECK_EQ(FindSnapshot(snapshots, different_transport_and_protocol).sent_bytes, 0ULL);
    CHECK_EQ(FindSnapshot(snapshots, different_transport_and_protocol).received_bytes, 400ULL);
}

void TestConnectionAggregationUsesAllEndpointAndProtocolFields() {
    ConnectionAggregator aggregator;
    const ProcessInstanceId process{100, 1};
    const auto observed = std::chrono::steady_clock::time_point{} + std::chrono::seconds(4);
    const ConnectionKey first = MakeConnectionKey(process, TransportProtocol::Tcp,
                                                  ApplicationProtocol::HttpsTls, 50000, 443);
    const ConnectionKey different_port = MakeConnectionKey(process, TransportProtocol::Tcp,
                                                           ApplicationProtocol::HttpsTls, 50001, 443);
    const ConnectionKey different_address = MakeConnectionKey(
        process, TransportProtocol::Tcp, ApplicationProtocol::HttpsTls, 50000, 443,
        MakeIpv4Address(10, 0, 0, 2));
    const ConnectionKey different_transport = MakeConnectionKey(process, TransportProtocol::Udp,
                                                                ApplicationProtocol::HttpsTls, 50000, 443);
    ConnectionKey different_remote_port = first;
    different_remote_port.remote.port = 444;
    ConnectionKey different_remote_address = first;
    different_remote_address.remote.address = MakeIpv4Address(1, 1, 1, 1);
    const ConnectionKey different_application = MakeConnectionKey(process, TransportProtocol::Tcp,
                                                                  ApplicationProtocol::Http, 50000, 443);
    const ConnectionKey different_process = MakeConnectionKey({100, 2}, TransportProtocol::Tcp,
                                                              ApplicationProtocol::HttpsTls, 50000, 443);

    aggregator.Add({first, L"browser.exe", TrafficDirection::Send, 100, observed});
    aggregator.Add({first, L"browser.exe", TrafficDirection::Receive, 200,
                    observed + std::chrono::seconds(2)});
    aggregator.Add({different_port, L"browser.exe", TrafficDirection::Send, 300, observed});
    aggregator.Add({different_address, L"browser.exe", TrafficDirection::Send, 400, observed});
    aggregator.Add({different_transport, L"browser.exe", TrafficDirection::Send, 500, observed});
    aggregator.Add({different_remote_port, L"browser.exe", TrafficDirection::Send, 550, observed});
    aggregator.Add({different_remote_address, L"browser.exe", TrafficDirection::Send, 575, observed});
    aggregator.Add({different_application, L"browser.exe", TrafficDirection::Send, 600, observed});
    aggregator.Add({different_process, L"other.exe", TrafficDirection::Send, 700, observed});
    aggregator.Add({first, L"renamed.exe", TrafficDirection::Send, 1,
                    observed + std::chrono::seconds(1)});

    const auto snapshots = aggregator.Snapshot(process, observed);
    CHECK_EQ(snapshots.size(), 7U);
    CHECK_EQ(FindConnectionSnapshot(snapshots, first).sent_bytes, 101ULL);
    CHECK_EQ(FindConnectionSnapshot(snapshots, first).received_bytes, 200ULL);
    CHECK_EQ(FindConnectionSnapshot(snapshots, first).process_name, L"renamed.exe");
    CHECK_EQ(FindConnectionSnapshot(snapshots, first).last_activity ==
                 observed + std::chrono::seconds(2),
             true);
    CHECK_EQ(FindConnectionSnapshot(snapshots, different_port).sent_bytes, 300ULL);
    CHECK_EQ(FindConnectionSnapshot(snapshots, different_address).sent_bytes, 400ULL);
    CHECK_EQ(FindConnectionSnapshot(snapshots, different_transport).sent_bytes, 500ULL);
    CHECK_EQ(FindConnectionSnapshot(snapshots, different_remote_port).sent_bytes, 550ULL);
    CHECK_EQ(FindConnectionSnapshot(snapshots, different_remote_address).sent_bytes, 575ULL);
    CHECK_EQ(FindConnectionSnapshot(snapshots, different_application).sent_bytes, 600ULL);
    CHECK_EQ(aggregator.Snapshot(different_process.process, observed).size(), 1U);
}

void TestConnectionAggregationSaturatesDirectionalCounters() {
    ConnectionAggregator aggregator;
    const auto key = MakeConnectionKey({101, 1}, TransportProtocol::Tcp,
                                       ApplicationProtocol::HttpsTls, 50000, 443);
    const auto observed = std::chrono::steady_clock::time_point{};

    aggregator.Add({key, L"browser.exe", TrafficDirection::Send,
                    std::numeric_limits<std::uint64_t>::max() - 1, observed});
    aggregator.Add({key, L"browser.exe", TrafficDirection::Send, 2, observed});
    aggregator.Add({key, L"browser.exe", TrafficDirection::Receive,
                    std::numeric_limits<std::uint64_t>::max() - 1, observed});
    aggregator.Add({key, L"browser.exe", TrafficDirection::Receive, 2, observed});

    const auto snapshot = FindConnectionSnapshot(aggregator.Snapshot(key.process, observed), key);
    CHECK_EQ(snapshot.sent_bytes, std::numeric_limits<std::uint64_t>::max());
    CHECK_EQ(snapshot.received_bytes, std::numeric_limits<std::uint64_t>::max());
}

void TestConnectionSnapshotsKeepProcessBaselinesIndependent() {
    ConnectionAggregator aggregator;
    const auto t0 = std::chrono::steady_clock::time_point{};
    const auto first = MakeConnectionKey({102, 1}, TransportProtocol::Tcp,
                                         ApplicationProtocol::HttpsTls, 50000, 443);
    const auto second = MakeConnectionKey({103, 1}, TransportProtocol::Tcp,
                                          ApplicationProtocol::HttpsTls, 50001, 443);

    aggregator.Add({first, L"first.exe", TrafficDirection::Send, 10, t0});
    aggregator.Add({second, L"second.exe", TrafficDirection::Send, 10, t0});
    CHECK_EQ(FindConnectionSnapshot(aggregator.Snapshot(first.process, t0), first)
                 .sent_bytes_per_second,
             0.0);
    CHECK_EQ(FindConnectionSnapshot(aggregator.Snapshot(second.process, t0 + std::chrono::seconds(1)),
                                    second)
                 .sent_bytes_per_second,
             0.0);

    aggregator.Add({first, L"first.exe", TrafficDirection::Send, 20, t0});
    aggregator.Add({second, L"second.exe", TrafficDirection::Send, 40, t0});
    CHECK_EQ(FindConnectionSnapshot(aggregator.Snapshot(first.process, t0 + std::chrono::seconds(2)),
                                    first)
                 .sent_bytes_per_second,
             10.0);
    CHECK_EQ(FindConnectionSnapshot(aggregator.Snapshot(second.process, t0 + std::chrono::seconds(5)),
                                    second)
                 .sent_bytes_per_second,
             10.0);
    CHECK_EQ(FindConnectionSnapshot(aggregator.Snapshot(first.process, t0 + std::chrono::seconds(3)),
                                    first)
                 .sent_bytes_per_second,
             0.0);

    aggregator.Add({first, L"first.exe", TrafficDirection::Send, 100, t0});
    CHECK_EQ(FindConnectionSnapshot(aggregator.Snapshot(first.process, t0 + std::chrono::seconds(3)),
                                    first)
                 .sent_bytes_per_second,
             0.0);
    CHECK_EQ(FindConnectionSnapshot(aggregator.Snapshot(first.process, t0 + std::chrono::seconds(2)),
                                    first)
                 .sent_bytes_per_second,
             0.0);
    aggregator.Add({first, L"first.exe", TrafficDirection::Send, 50, t0});
    CHECK_EQ(FindConnectionSnapshot(aggregator.Snapshot(first.process, t0 + std::chrono::seconds(6)),
                                    first)
                 .sent_bytes_per_second,
             50.0);

    aggregator.ResetSnapshotBaseline(first.process);
    CHECK_EQ(FindConnectionSnapshot(aggregator.Snapshot(first.process, t0 + std::chrono::seconds(7)),
                                    first)
                 .sent_bytes_per_second,
             0.0);
    aggregator.Add({first, L"first.exe", TrafficDirection::Send, 30, t0});
    CHECK_EQ(FindConnectionSnapshot(aggregator.Snapshot(first.process, t0 + std::chrono::seconds(9)),
                                    first)
                 .sent_bytes_per_second,
             15.0);
}

void TestConnectionAggregationBoundsEntriesAndClearsState() {
    ConnectionAggregator aggregator(2);
    const auto t0 = std::chrono::steady_clock::time_point{};
    const auto first = MakeConnectionKey({104, 1}, TransportProtocol::Tcp,
                                         ApplicationProtocol::HttpsTls, 50000, 443);
    const auto second = MakeConnectionKey({104, 1}, TransportProtocol::Tcp,
                                          ApplicationProtocol::HttpsTls, 50001, 443);
    const auto rejected = MakeConnectionKey({104, 1}, TransportProtocol::Tcp,
                                            ApplicationProtocol::HttpsTls, 50002, 443);

    aggregator.Add({first, L"first.exe", TrafficDirection::Send, 1, t0});
    aggregator.Add({second, L"first.exe", TrafficDirection::Send, 2, t0});
    aggregator.Add({rejected, L"first.exe", TrafficDirection::Send, 3, t0});
    aggregator.Add({rejected, L"first.exe", TrafficDirection::Send, 4, t0});
    aggregator.Add({first, L"first.exe", TrafficDirection::Send, 5, t0});

    const auto snapshots = aggregator.Snapshot(first.process, t0);
    CHECK_EQ(snapshots.size(), 2U);
    CHECK_EQ(FindConnectionSnapshot(snapshots, first).sent_bytes, 6ULL);
    CHECK_EQ(aggregator.dropped_detail_events(), 2ULL);

    aggregator.Clear();
    CHECK_EQ(aggregator.Snapshot(first.process, t0 + std::chrono::seconds(1)).size(), 0U);
    CHECK_EQ(aggregator.dropped_detail_events(), 0ULL);
    aggregator.Add({first, L"first.exe", TrafficDirection::Send, 1, t0});
    CHECK_EQ(FindConnectionSnapshot(aggregator.Snapshot(first.process, t0 + std::chrono::seconds(2)),
                                    first)
                 .sent_bytes_per_second,
             0.0);
}

void TestConnectionClearResetsProcessSnapshotTimeBaseline() {
    ConnectionAggregator aggregator;
    const auto t0 = std::chrono::steady_clock::time_point{};
    const auto key = MakeConnectionKey({105, 1}, TransportProtocol::Tcp,
                                       ApplicationProtocol::HttpsTls, 50000, 443);

    aggregator.Add({key, L"first.exe", TrafficDirection::Send, 10, t0});
    aggregator.Snapshot(key.process, t0 + std::chrono::seconds(10));
    aggregator.Clear();

    aggregator.Add({key, L"first.exe", TrafficDirection::Send, 5, t0});
    CHECK_EQ(FindConnectionSnapshot(aggregator.Snapshot(key.process, t0), key)
                 .sent_bytes_per_second,
             0.0);
    aggregator.Add({key, L"first.exe", TrafficDirection::Send, 6, t0});
    CHECK_EQ(FindConnectionSnapshot(aggregator.Snapshot(key.process, t0 + std::chrono::seconds(2)),
                                    key)
                 .sent_bytes_per_second,
             3.0);
}

void TestConnectionAggregationDefaultCapacityIsOneHundredThousand() {
    ConnectionAggregator aggregator;
    const auto observed = std::chrono::steady_clock::time_point{};
    for (std::uint32_t index = 0; index < 100000; ++index) {
        const auto key = MakeConnectionKey({1000 + index, 1}, TransportProtocol::Tcp,
                                           ApplicationProtocol::HttpsTls, 50000, 443);
        aggregator.Add({key, L"browser.exe", TrafficDirection::Send, 1, observed});
    }
    const auto rejected = MakeConnectionKey({101000, 1}, TransportProtocol::Tcp,
                                            ApplicationProtocol::HttpsTls, 50000, 443);
    aggregator.Add({rejected, L"browser.exe", TrafficDirection::Send, 1, observed});

    CHECK_EQ(aggregator.dropped_detail_events(), 1ULL);
}

void TestEtwPayloadDecodeIsBoundedAndUsesNetworkOrderPorts() {
    const EventLayout layout = MakeIpv4Layout(TrafficDirection::Send, TransportProtocol::Tcp);
    const std::array payload{
        std::byte{0x78}, std::byte{0x56}, std::byte{0x34}, std::byte{0x12},
        std::byte{0x04}, std::byte{0x03}, std::byte{0x02}, std::byte{0x01},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{0xAB}, std::byte{0xCD}, std::byte{0x12}, std::byte{0x34},
    };

    const auto decoded = DecodePayload(layout, payload);
    CHECK_EQ(decoded.has_value(), true);
    if (decoded) {
        CHECK_EQ(decoded->pid, 0x12345678U);
        CHECK_EQ(decoded->bytes, 0x01020304ULL);
        CHECK_EQ(decoded->source_port, 0x1234U);
        CHECK_EQ(decoded->destination_port, 0xABCDU);
        CHECK_EQ(static_cast<int>(decoded->direction), static_cast<int>(TrafficDirection::Send));
        CHECK_EQ(static_cast<int>(decoded->transport), static_cast<int>(TransportProtocol::Tcp));
    }

    CHECK_EQ(DecodePayload(layout, std::span{payload}.first(payload.size() - 1)).has_value(),
             false);
    CHECK_EQ(DecodePayload(layout, {}).has_value(), false);

    auto missing_field = layout;
    missing_field.pid.width = 0;
    CHECK_EQ(DecodePayload(missing_field, payload).has_value(), false);

    auto unsupported_width = layout;
    unsupported_width.size.width = 8;
    CHECK_EQ(DecodePayload(unsupported_width, payload).has_value(), false);

    auto overflowing_offset = layout;
    overflowing_offset.pid.offset = std::numeric_limits<std::size_t>::max();
    CHECK_EQ(DecodePayload(overflowing_offset, payload).has_value(), false);
}

void TestEtwPayloadDecodeCopiesIpv4EndpointAddresses() {
    EventLayout ipv4{};
    ipv4.pid = {0, 4};
    ipv4.size = {4, 4};
    ipv4.destination_address = {8, 4};
    ipv4.source_address = {12, 4};
    ipv4.destination_port = {16, 2};
    ipv4.source_port = {18, 2};
    ipv4.direction = TrafficDirection::Send;
    ipv4.transport = TransportProtocol::Tcp;
    ipv4.address_family = IpAddressFamily::V4;

    const std::array payload{
        std::byte{0x78}, std::byte{0x56}, std::byte{0x34}, std::byte{0x12},
        std::byte{0x04}, std::byte{0x03}, std::byte{0x02}, std::byte{0x01},
        std::byte{198}, std::byte{51}, std::byte{100}, std::byte{2},
        std::byte{192}, std::byte{0}, std::byte{2}, std::byte{1},
        std::byte{0xAB}, std::byte{0xCD}, std::byte{0x12}, std::byte{0x34},
    };
    const std::array<std::byte, 16> expected_source{
        std::byte{192}, std::byte{0}, std::byte{2}, std::byte{1}};
    const std::array<std::byte, 16> expected_destination{
        std::byte{198}, std::byte{51}, std::byte{100}, std::byte{2}};

    const auto decoded = DecodePayload(ipv4, payload);
    CHECK_EQ(decoded.has_value(), true);
    if (decoded) {
        CHECK_EQ(decoded->pid, 0x12345678U);
        CHECK_EQ(decoded->bytes, 0x01020304ULL);
        CHECK_EQ(static_cast<int>(decoded->direction), static_cast<int>(TrafficDirection::Send));
        CHECK_EQ(static_cast<int>(decoded->transport), static_cast<int>(TransportProtocol::Tcp));
        CHECK_EQ(static_cast<int>(decoded->source_address.family), static_cast<int>(IpAddressFamily::V4));
        CHECK_EQ(static_cast<int>(decoded->destination_address.family), static_cast<int>(IpAddressFamily::V4));
        CHECK_EQ(decoded->source_port, 0x1234U);
        CHECK_EQ(decoded->destination_port, 0xABCDU);
        for (std::size_t index = 0; index < expected_source.size(); ++index) {
            CHECK_EQ(std::to_integer<int>(decoded->source_address.bytes[index]),
                     std::to_integer<int>(expected_source[index]));
            CHECK_EQ(std::to_integer<int>(decoded->destination_address.bytes[index]),
                     std::to_integer<int>(expected_destination[index]));
        }
    }
}

void TestEtwPayloadDecodeCopiesIpv6EndpointAddresses() {
    EventLayout ipv6{};
    ipv6.pid = {0, 4};
    ipv6.size = {4, 4};
    ipv6.destination_address = {8, 16};
    ipv6.source_address = {24, 16};
    ipv6.destination_port = {40, 2};
    ipv6.source_port = {42, 2};
    ipv6.direction = TrafficDirection::Receive;
    ipv6.transport = TransportProtocol::Udp;
    ipv6.address_family = IpAddressFamily::V6;

    const std::array payload{
        std::byte{0x2A}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{0x40}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{0x20}, std::byte{0x01}, std::byte{0x0D}, std::byte{0xB8},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{2},
        std::byte{0x20}, std::byte{0x01}, std::byte{0x0D}, std::byte{0xB8},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1},
        std::byte{0xC0}, std::byte{0}, std::byte{0}, std::byte{0x35},
    };
    const std::array<std::byte, 16> expected_source{
        std::byte{0x20}, std::byte{0x01}, std::byte{0x0D}, std::byte{0xB8},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1}};
    const std::array<std::byte, 16> expected_destination{
        std::byte{0x20}, std::byte{0x01}, std::byte{0x0D}, std::byte{0xB8},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{2}};

    const auto decoded = DecodePayload(ipv6, payload);
    CHECK_EQ(decoded.has_value(), true);
    if (decoded) {
        CHECK_EQ(decoded->pid, 42U);
        CHECK_EQ(decoded->bytes, 64ULL);
        CHECK_EQ(static_cast<int>(decoded->direction), static_cast<int>(TrafficDirection::Receive));
        CHECK_EQ(static_cast<int>(decoded->transport), static_cast<int>(TransportProtocol::Udp));
        CHECK_EQ(static_cast<int>(decoded->source_address.family), static_cast<int>(IpAddressFamily::V6));
        CHECK_EQ(static_cast<int>(decoded->destination_address.family), static_cast<int>(IpAddressFamily::V6));
        CHECK_EQ(decoded->source_port, 53U);
        CHECK_EQ(decoded->destination_port, 49152U);
        for (std::size_t index = 0; index < expected_source.size(); ++index) {
            CHECK_EQ(std::to_integer<int>(decoded->source_address.bytes[index]),
                     std::to_integer<int>(expected_source[index]));
            CHECK_EQ(std::to_integer<int>(decoded->destination_address.bytes[index]),
                     std::to_integer<int>(expected_destination[index]));
        }
    }

    CHECK_EQ(DecodePayload(ipv6, std::span{payload}.first(39)).has_value(), false);

    auto wrong_width = ipv6;
    wrong_width.source_address.width = 4;
    const auto wrong_width_payload = payload;
    CHECK_EQ(DecodePayload(wrong_width, wrong_width_payload).has_value(), false);
}

void TestParseEventLayoutMapsActualTcpIpv4MofOrder() {
    const SchemaFixture schema{{L"PID", TDH_INTYPE_UINT32},
                               {L"size", TDH_INTYPE_UINT32},
                               {L"daddr", TDH_INTYPE_BINARY, 4},
                               {L"saddr", TDH_INTYPE_BINARY, 4},
                               {L"dport", TDH_INTYPE_UINT16},
                               {L"sport", TDH_INTYPE_UINT16}};
    const auto record = MakeNetworkRecord(kTestTcpIpProvider, EVENT_TRACE_TYPE_SEND);
    const auto layout = ParseEventLayout(record, schema.bytes());

    CHECK_EQ(layout.has_value(), true);
    if (!layout) {
        return;
    }
    CHECK_EQ(layout->destination_address.offset, 8U);
    CHECK_EQ(layout->source_address.offset, 12U);
    CHECK_EQ(layout->destination_port.offset, 16U);
    CHECK_EQ(layout->source_port.offset, 18U);
    CHECK_EQ(static_cast<int>(layout->address_family), static_cast<int>(IpAddressFamily::V4));

    const std::array payload{
        std::byte{0x78}, std::byte{0x56}, std::byte{0x34}, std::byte{0x12},
        std::byte{0x04}, std::byte{0x03}, std::byte{0x02}, std::byte{0x01},
        std::byte{198}, std::byte{51}, std::byte{100}, std::byte{2},
        std::byte{192}, std::byte{0}, std::byte{2}, std::byte{1},
        std::byte{0xAB}, std::byte{0xCD}, std::byte{0x12}, std::byte{0x34},
    };
    const auto decoded = DecodePayload(*layout, payload);
    CHECK_EQ(decoded.has_value(), true);
    if (decoded) {
        CHECK_EQ(std::to_integer<int>(decoded->source_address.bytes[0]), 192);
        CHECK_EQ(std::to_integer<int>(decoded->source_address.bytes[3]), 1);
        CHECK_EQ(std::to_integer<int>(decoded->destination_address.bytes[0]), 198);
        CHECK_EQ(std::to_integer<int>(decoded->destination_address.bytes[3]), 2);
        CHECK_EQ(decoded->source_port, 0x1234U);
        CHECK_EQ(decoded->destination_port, 0xABCDU);
    }
}

void TestParseEventLayoutMapsActualUdpIpv6MofOrder() {
    const SchemaFixture schema{{L"PID", TDH_INTYPE_UINT32},
                               {L"size", TDH_INTYPE_UINT32},
                               {L"daddr", TDH_INTYPE_BINARY, 16},
                               {L"saddr", TDH_INTYPE_BINARY, 16},
                               {L"dport", TDH_INTYPE_UINT16},
                               {L"sport", TDH_INTYPE_UINT16}};
    const auto record = MakeNetworkRecord(
        kTestUdpIpProvider, static_cast<std::uint8_t>(EVENT_TRACE_TYPE_RECEIVE + 16));
    const auto layout = ParseEventLayout(record, schema.bytes());

    CHECK_EQ(layout.has_value(), true);
    if (!layout) {
        return;
    }
    CHECK_EQ(layout->destination_address.offset, 8U);
    CHECK_EQ(layout->source_address.offset, 24U);
    CHECK_EQ(layout->destination_port.offset, 40U);
    CHECK_EQ(layout->source_port.offset, 42U);
    CHECK_EQ(static_cast<int>(layout->address_family), static_cast<int>(IpAddressFamily::V6));

    const std::array payload{
        std::byte{0x2A}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{0x40}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{0x20}, std::byte{0x01}, std::byte{0x0D}, std::byte{0xB8},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{2},
        std::byte{0x20}, std::byte{0x01}, std::byte{0x0D}, std::byte{0xB8},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1},
        std::byte{0xC0}, std::byte{0}, std::byte{0}, std::byte{0x35},
    };
    const auto decoded = DecodePayload(*layout, payload);
    CHECK_EQ(decoded.has_value(), true);
    if (decoded) {
        CHECK_EQ(std::to_integer<int>(decoded->source_address.bytes[0]), 0x20);
        CHECK_EQ(std::to_integer<int>(decoded->source_address.bytes[15]), 1);
        CHECK_EQ(std::to_integer<int>(decoded->destination_address.bytes[0]), 0x20);
        CHECK_EQ(std::to_integer<int>(decoded->destination_address.bytes[15]), 2);
        CHECK_EQ(decoded->source_port, 53U);
        CHECK_EQ(decoded->destination_port, 49152U);
    }
}

void TestParseEventLayoutRejectsTargetAddressWidthMismatch() {
    const SchemaFixture schema{{L"PID", TDH_INTYPE_UINT32},
                               {L"size", TDH_INTYPE_UINT32},
                               {L"daddr", TDH_INTYPE_BINARY, 16},
                               {L"saddr", TDH_INTYPE_BINARY, 4},
                               {L"dport", TDH_INTYPE_UINT16},
                               {L"sport", TDH_INTYPE_UINT16}};
    const auto record = MakeNetworkRecord(kTestTcpIpProvider, EVENT_TRACE_TYPE_SEND);
    CHECK_EQ(ParseEventLayout(record, schema.bytes()).has_value(), false);
}

void TestParseEventLayoutRejectsDuplicateTargetAddressProperty() {
    const SchemaFixture schema{{L"PID", TDH_INTYPE_UINT32},
                               {L"size", TDH_INTYPE_UINT32},
                               {L"daddr", TDH_INTYPE_BINARY, 4},
                               {L"saddr", TDH_INTYPE_BINARY, 4},
                               {L"SADDR", TDH_INTYPE_BINARY, 4},
                               {L"dport", TDH_INTYPE_UINT16},
                               {L"sport", TDH_INTYPE_UINT16}};
    const auto record = MakeNetworkRecord(kTestTcpIpProvider, EVENT_TRACE_TYPE_SEND);
    CHECK_EQ(ParseEventLayout(record, schema.bytes()).has_value(), false);
}

void TestParseEventLayoutRejectsMissingTargetAddressProperty() {
    const SchemaFixture schema{{L"PID", TDH_INTYPE_UINT32},
                               {L"size", TDH_INTYPE_UINT32},
                               {L"daddr", TDH_INTYPE_BINARY, 4},
                               {L"dport", TDH_INTYPE_UINT16},
                               {L"sport", TDH_INTYPE_UINT16}};
    const auto record = MakeNetworkRecord(kTestTcpIpProvider, EVENT_TRACE_TYPE_SEND);
    CHECK_EQ(ParseEventLayout(record, schema.bytes()).has_value(), false);
}

void TestParseEventLayoutRejectsVariableTargetAddressProperty() {
    const SchemaFixture schema{{L"PID", TDH_INTYPE_UINT32},
                               {L"size", TDH_INTYPE_UINT32},
                               {L"daddr", TDH_INTYPE_BINARY, 4},
                               {L"saddr", TDH_INTYPE_BINARY, 4, PropertyParamLength},
                               {L"dport", TDH_INTYPE_UINT16},
                               {L"sport", TDH_INTYPE_UINT16}};
    const auto record = MakeNetworkRecord(kTestTcpIpProvider, EVENT_TRACE_TYPE_SEND);
    CHECK_EQ(ParseEventLayout(record, schema.bytes()).has_value(), false);
}

void TestEtwDecoderCachesLayoutsBySchemaKey() {
    const EventLayout layout = MakeIpv4Layout(TrafficDirection::Receive, TransportProtocol::Udp);
    const std::array payload{
        std::byte{0x2A}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x40}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{127}, std::byte{0}, std::byte{0}, std::byte{1},
        std::byte{127}, std::byte{0}, std::byte{0}, std::byte{1},
        std::byte{0xC0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x35},
    };
    int load_count = 0;
    EtwDecoder decoder([&](const EVENT_RECORD&) -> std::optional<EventLayout> {
        ++load_count;
        return layout;
    });

    EVENT_RECORD record{};
    record.EventHeader.ProviderId =
        GUID{0xbf3a50c5, 0xa9c9, 0x4988, {0xa0, 0x05, 0x2d, 0xf0, 0xb7, 0xc8, 0x0f, 0x80}};
    record.EventHeader.EventDescriptor.Opcode = EVENT_TRACE_TYPE_RECEIVE;
    record.EventHeader.EventDescriptor.Version = 1;
    record.EventHeader.Flags = EVENT_HEADER_FLAG_CLASSIC_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER;
    record.UserData = const_cast<std::byte*>(payload.data());
    record.UserDataLength = static_cast<USHORT>(payload.size());

    const auto first_decoded = decoder.Decode(record);
    CHECK_EQ(first_decoded.has_value(), true);
    if (first_decoded) {
        CHECK_EQ(static_cast<int>(first_decoded->source_address.family),
                 static_cast<int>(IpAddressFamily::V4));
        CHECK_EQ(static_cast<int>(first_decoded->destination_address.family),
                 static_cast<int>(IpAddressFamily::V4));
        CHECK_EQ(std::to_integer<int>(first_decoded->source_address.bytes[0]), 127);
        CHECK_EQ(std::to_integer<int>(first_decoded->destination_address.bytes[0]), 127);
    }
    CHECK_EQ(decoder.Decode(record).has_value(), true);
    CHECK_EQ(load_count, 1);
    CHECK_EQ(decoder.cached_layout_count(), 1U);

    record.EventHeader.EventDescriptor.Version = 2;
    CHECK_EQ(decoder.Decode(record).has_value(), true);
    CHECK_EQ(load_count, 2);
    CHECK_EQ(decoder.cached_layout_count(), 2U);
    CHECK_EQ(decoder.parse_failures(), 0ULL);

    record.EventHeader.Flags = EVENT_HEADER_FLAG_CLASSIC_HEADER | EVENT_HEADER_FLAG_32_BIT_HEADER;
    CHECK_EQ(decoder.Decode(record).has_value(), true);
    CHECK_EQ(load_count, 3);
    CHECK_EQ(decoder.cached_layout_count(), 3U);
}

void TestEtwDecoderCachesFailedParsedAddressSchemasOnlyForTargetEvents() {
    const SchemaFixture schema{{L"PID", TDH_INTYPE_UINT32},
                               {L"size", TDH_INTYPE_UINT32},
                               {L"daddr", TDH_INTYPE_BINARY, 16},
                               {L"saddr", TDH_INTYPE_BINARY, 4},
                               {L"dport", TDH_INTYPE_UINT16},
                               {L"sport", TDH_INTYPE_UINT16}};
    int load_count = 0;
    EtwDecoder decoder([&](const EVENT_RECORD& record) -> std::optional<EventLayout> {
        ++load_count;
        return ParseEventLayout(record, schema.bytes());
    });
    const auto record = MakeNetworkRecord(kTestTcpIpProvider, EVENT_TRACE_TYPE_SEND);

    CHECK_EQ(decoder.Decode(record).has_value(), false);
    CHECK_EQ(decoder.Decode(record).has_value(), false);
    CHECK_EQ(load_count, 1);
    CHECK_EQ(decoder.cached_layout_count(), 1U);
    CHECK_EQ(decoder.parse_failures(), 2ULL);

    auto ignored = record;
    ignored.EventHeader.ProviderId = GUID_NULL;
    CHECK_EQ(decoder.Decode(ignored).has_value(), false);
    CHECK_EQ(load_count, 1);
    CHECK_EQ(decoder.parse_failures(), 2ULL);
}

void TestEtwDecoderCachesInvalidLayoutsAndCountsEveryFailedEvent() {
    int load_count = 0;
    EtwDecoder decoder([&](const EVENT_RECORD&) -> std::optional<EventLayout> {
        ++load_count;
        return std::nullopt;
    });
    EVENT_RECORD record{};
    record.EventHeader.ProviderId =
        GUID{0x9a280ac0, 0xc8e0, 0x11d1, {0x84, 0xe2, 0x00, 0xc0, 0x4f, 0xb9, 0x98, 0xa2}};
    record.EventHeader.EventDescriptor.Opcode = EVENT_TRACE_TYPE_SEND;
    record.EventHeader.EventDescriptor.Version = 2;
    record.EventHeader.Flags = EVENT_HEADER_FLAG_CLASSIC_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER;

    CHECK_EQ(decoder.Decode(record).has_value(), false);
    CHECK_EQ(decoder.Decode(record).has_value(), false);
    CHECK_EQ(load_count, 1);
    CHECK_EQ(decoder.cached_layout_count(), 1U);
    CHECK_EQ(decoder.parse_failures(), 2ULL);
}

void TestEtwDecoderIgnoresNonNetworkAndNonDataEvents() {
    int load_count = 0;
    EtwDecoder decoder([&](const EVENT_RECORD&) -> std::optional<EventLayout> {
        ++load_count;
        return std::nullopt;
    });
    EVENT_RECORD record{};
    record.EventHeader.ProviderId = GUID_NULL;
    record.EventHeader.EventDescriptor.Opcode = EVENT_TRACE_TYPE_SEND;
    record.EventHeader.Flags = EVENT_HEADER_FLAG_64_BIT_HEADER;

    CHECK_EQ(decoder.Decode(record).has_value(), false);

    record.EventHeader.ProviderId =
        GUID{0x9a280ac0, 0xc8e0, 0x11d1, {0x84, 0xe2, 0x00, 0xc0, 0x4f, 0xb9, 0x98, 0xa2}};
    record.EventHeader.EventDescriptor.Opcode = EVENT_TRACE_TYPE_CONNECT;
    CHECK_EQ(decoder.Decode(record).has_value(), false);

    record.EventHeader.EventDescriptor.Opcode = EVENT_TRACE_TYPE_SEND;
    record.EventHeader.Flags = 0;
    CHECK_EQ(decoder.Decode(record).has_value(), false);

    CHECK_EQ(load_count, 0);
    CHECK_EQ(decoder.cached_layout_count(), 0U);
    CHECK_EQ(decoder.parse_failures(), 0ULL);
}

void TestSyntheticRecordFlowsThroughDecodeResolveClassifyAndAggregate() {
    const EventLayout layout = MakeIpv4Layout(TrafficDirection::Send, TransportProtocol::Tcp);
    const std::array payload{
        std::byte{0xD2}, std::byte{0x04}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x08}, std::byte{0x00}, std::byte{0x00},
        std::byte{127}, std::byte{0}, std::byte{0}, std::byte{1},
        std::byte{192}, std::byte{0}, std::byte{2}, std::byte{1},
        std::byte{0xC3}, std::byte{0x50}, std::byte{0x01}, std::byte{0xBB},
    };
    EtwDecoder decoder([&](const EVENT_RECORD&) -> std::optional<EventLayout> {
        return layout;
    });
    EVENT_RECORD record{};
    record.EventHeader.ProviderId =
        GUID{0x9a280ac0, 0xc8e0, 0x11d1, {0x84, 0xe2, 0x00, 0xc0, 0x4f, 0xb9, 0x98, 0xa2}};
    record.EventHeader.EventDescriptor.Opcode = EVENT_TRACE_TYPE_SEND;
    record.EventHeader.Flags = EVENT_HEADER_FLAG_64_BIT_HEADER;
    record.UserData = const_cast<std::byte*>(payload.data());
    record.UserDataLength = static_cast<USHORT>(payload.size());

    FakeProcessInfoApi process_api;
    process_api.query_results = {ProcessInfo{{1234, 55}, L"browser.exe", true}};
    ProcessInfoCache process_cache(process_api);
    TrafficAggregator aggregator;
    const auto decoded = decoder.Decode(record);
    CHECK_EQ(decoded.has_value(), true);
    if (decoded) {
        const auto process = process_cache.Resolve(decoded->pid, 1);
        const auto application = InferApplicationProtocol(
            decoded->transport, decoded->direction, decoded->source_port,
            decoded->destination_port);
        aggregator.Add({{process.id, decoded->transport, application}, process.name,
                        decoded->direction, decoded->bytes});
    }

    const auto snapshots = aggregator.Snapshot(std::chrono::steady_clock::time_point{});
    const TrafficKey expected{{1234, 55}, TransportProtocol::Tcp,
                              ApplicationProtocol::HttpsTls};
    CHECK_EQ(snapshots.size(), 1U);
    CHECK_EQ(FindSnapshot(snapshots, expected).sent_bytes, 2048ULL);
}

void TestTrafficRatesClearAndSaturation() {
    TrafficAggregator aggregator;
    const auto t0 = std::chrono::steady_clock::time_point{};
    const TrafficKey key{{100, 1}, TransportProtocol::Tcp, ApplicationProtocol::HttpsTls};

    aggregator.Add({key, L"first.exe", TrafficDirection::Send, 0});
    const auto first_snapshots = aggregator.Snapshot(t0);
    CHECK_EQ(FindSnapshot(first_snapshots, key).sent_bytes_per_second, 0.0);
    CHECK_EQ(FindSnapshot(first_snapshots, key).received_bytes_per_second, 0.0);

    aggregator.Add({key, L"first.exe", TrafficDirection::Send, 2048});
    aggregator.Add({key, L"first.exe", TrafficDirection::Receive, 1024});
    const auto second_snapshots = aggregator.Snapshot(t0 + std::chrono::seconds(2));
    CHECK_EQ(FindSnapshot(second_snapshots, key).sent_bytes_per_second, 1024.0);
    CHECK_EQ(FindSnapshot(second_snapshots, key).received_bytes_per_second, 512.0);

    aggregator.Clear();
    CHECK_EQ(aggregator.Snapshot(t0 + std::chrono::seconds(3)).size(), 0U);
    aggregator.Add({key, L"first.exe", TrafficDirection::Send, 1});
    const auto after_clear_snapshots = aggregator.Snapshot(t0 + std::chrono::seconds(4));
    CHECK_EQ(FindSnapshot(after_clear_snapshots, key).sent_bytes_per_second, 0.0);

    TrafficAggregator overflow_aggregator;
    overflow_aggregator.Add({key, L"first.exe", TrafficDirection::Send,
                             std::numeric_limits<std::uint64_t>::max() - 1});
    overflow_aggregator.Add({key, L"first.exe", TrafficDirection::Send, 2});
    const auto overflow_snapshots = overflow_aggregator.Snapshot(t0);
    CHECK_EQ(FindSnapshot(overflow_snapshots, key).sent_bytes,
             std::numeric_limits<std::uint64_t>::max());

    TrafficAggregator receive_overflow_aggregator;
    receive_overflow_aggregator.Add({key, L"first.exe", TrafficDirection::Receive,
                                     std::numeric_limits<std::uint64_t>::max() - 1});
    receive_overflow_aggregator.Add({key, L"first.exe", TrafficDirection::Receive, 2});
    CHECK_EQ(FindSnapshot(receive_overflow_aggregator.Snapshot(t0), key).received_bytes,
             std::numeric_limits<std::uint64_t>::max());
}

void TestTrafficRatesIgnoreNonpositiveSnapshotTimes() {
    TrafficAggregator aggregator;
    const auto t0 = std::chrono::steady_clock::time_point{};
    const TrafficKey key{{100, 1}, TransportProtocol::Tcp, ApplicationProtocol::HttpsTls};

    aggregator.Add({key, L"first.exe", TrafficDirection::Send, 0});
    aggregator.Snapshot(t0);
    aggregator.Add({key, L"first.exe", TrafficDirection::Send, 100});
    aggregator.Snapshot(t0 + std::chrono::seconds(2));

    aggregator.Add({key, L"first.exe", TrafficDirection::Send, 200});
    const auto equal_time_snapshots = aggregator.Snapshot(t0 + std::chrono::seconds(2));
    CHECK_EQ(FindSnapshot(equal_time_snapshots, key).sent_bytes_per_second, 0.0);
    const auto earlier_time_snapshots = aggregator.Snapshot(t0 + std::chrono::seconds(1));
    CHECK_EQ(FindSnapshot(earlier_time_snapshots, key).sent_bytes_per_second, 0.0);

    aggregator.Add({key, L"first.exe", TrafficDirection::Send, 100});
    const auto later_snapshots = aggregator.Snapshot(t0 + std::chrono::seconds(5));
    CHECK_EQ(FindSnapshot(later_snapshots, key).sent_bytes_per_second, 100.0);
}

void TestTrafficAggregationKeepsApplicationProtocolsSeparate() {
    TrafficAggregator aggregator;
    const auto t0 = std::chrono::steady_clock::time_point{};
    const TrafficKey https{{100, 1}, TransportProtocol::Tcp, ApplicationProtocol::HttpsTls};
    const TrafficKey http{{100, 1}, TransportProtocol::Tcp, ApplicationProtocol::Http};

    aggregator.Add({https, L"first.exe", TrafficDirection::Send, 100});
    aggregator.Add({http, L"first.exe", TrafficDirection::Receive, 200});

    const auto snapshots = aggregator.Snapshot(t0);
    CHECK_EQ(snapshots.size(), 2U);
    CHECK_EQ(FindSnapshot(snapshots, https).sent_bytes, 100ULL);
    CHECK_EQ(FindSnapshot(snapshots, https).received_bytes, 0ULL);
    CHECK_EQ(FindSnapshot(snapshots, http).sent_bytes, 0ULL);
    CHECK_EQ(FindSnapshot(snapshots, http).received_bytes, 200ULL);
}

TrafficSnapshot MakeSnapshot(TrafficKey key, std::wstring process_name,
                             double sent_bytes_per_second,
                             double received_bytes_per_second) {
    TrafficSnapshot snapshot;
    snapshot.key = key;
    snapshot.process_name = std::move(process_name);
    snapshot.sent_bytes_per_second = sent_bytes_per_second;
    snapshot.received_bytes_per_second = received_bytes_per_second;
    return snapshot;
}

void TestTrafficFormatting() {
    CHECK_EQ(FormatBytes(0), L"0 B");
    CHECK_EQ(FormatBytes(1024), L"1 KB");
    CHECK_EQ(FormatBytes(1536), L"1.5 KB");
    CHECK_EQ(FormatBytes(1024ULL * 1024 * 1024), L"1 GB");
    CHECK_EQ(FormatRate(2048.0), L"2 KB/s");
    CHECK_EQ(FormatRate(-1.0), L"0 B/s");
    CHECK_EQ(FormatRate(std::numeric_limits<double>::infinity()), L"0 B/s");
    CHECK_EQ(FormatRate(std::numeric_limits<double>::quiet_NaN()), L"0 B/s");
    CHECK_EQ(ProcessStatusText(true), L"运行中");
    CHECK_EQ(ProcessStatusText(false), L"已结束");
}

void TestConnectionRowsFormatAddressesAndClassifyActivity() {
    CHECK_EQ(FormatIpAddress(MakeIpv4Address(192, 0, 2, 1)), L"192.0.2.1");
    CHECK_EQ(FormatIpAddress(MakeIpv6Address(
                 {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})),
             L"2001:db8::1");
    CHECK_EQ(TransportProtocolName(TransportProtocol::Tcp), L"TCP");
    CHECK_EQ(TransportProtocolName(TransportProtocol::Udp), L"UDP");

    const auto t0 = std::chrono::steady_clock::time_point{};
    ConnectionSnapshot sent{MakeConnectionKey({1, 1}, TransportProtocol::Tcp,
                                               ApplicationProtocol::Http, 50000, 80),
                            L"browser.exe", 1, 0, 0, 0, t0};
    ConnectionSnapshot received{MakeConnectionKey({1, 1}, TransportProtocol::Tcp,
                                                   ApplicationProtocol::Http, 50001, 80),
                                L"browser.exe", 0, 1, 0, 0, t0 - std::chrono::seconds(1)};
    ConnectionSnapshot bidirectional{
        MakeConnectionKey({1, 1}, TransportProtocol::Tcp, ApplicationProtocol::Http, 50002, 80),
        L"browser.exe", 1, 1, 0, 0, t0 - std::chrono::seconds(6)};

    const auto rows = BuildConnectionRows({sent, received, bidirectional}, true,
                                          t0 + std::chrono::seconds(5));
    CHECK_EQ(rows.size(), 3ULL);
    if (rows.size() == 3) {
        CHECK_EQ(rows[0].direction, ConnectionDirection::SendOnly);
        CHECK_EQ(rows[0].status, ConnectionActivityStatus::Active);
        CHECK_EQ(rows[1].direction, ConnectionDirection::ReceiveOnly);
        CHECK_EQ(rows[1].status, ConnectionActivityStatus::Historical);
        CHECK_EQ(rows[2].direction, ConnectionDirection::Bidirectional);
        CHECK_EQ(rows[2].status, ConnectionActivityStatus::Historical);
    }

    const auto ended = BuildConnectionRows({sent}, false, t0 + std::chrono::seconds(5));
    CHECK_EQ(ended[0].status, ConnectionActivityStatus::ProcessEnded);
    CHECK_EQ(ConnectionActivityStatusText(ConnectionActivityStatus::Active), L"活跃");
    CHECK_EQ(ConnectionDirectionName(ConnectionDirection::Bidirectional), L"双向");
}

void TestConnectionRowsSortEveryColumnWithBinaryAndKeyTieBreakers() {
    const auto t0 = std::chrono::steady_clock::time_point{};
    // "443" precedes "80" lexically; ports must use their numeric values.
    ConnectionSnapshot first{
        MakeConnectionKey({20, 2}, TransportProtocol::Udp, ApplicationProtocol::Dns, 443, 443,
                          MakeIpv4Address(192, 0, 2, 1), MakeIpv4Address(10, 0, 0, 2)),
        L"Alpha.exe", 100, 200, 10.0, 20.0, t0};
    ConnectionSnapshot second{
        MakeConnectionKey({10, 1}, TransportProtocol::Tcp, ApplicationProtocol::Http, 80, 80,
                          MakeIpv4Address(2, 0, 0, 1), MakeIpv4Address(10, 0, 0, 1)),
        L"alpha.exe", 200, 100, 2.0, 1.0, t0 - std::chrono::seconds(6)};
    ConnectionSnapshot tied = first;
    tied.key.process = {30, 3};

    const auto rows = BuildConnectionRows({first, second, tied}, true, t0);
    CHECK_EQ(rows[0].connection.key, first.key);
    CHECK_EQ(rows[1].connection.key, tied.key);
    CHECK_EQ(rows[2].connection.key, second.key);

    auto sortable = rows;
    sortable[0].status = ConnectionActivityStatus::Active;
    sortable[0].direction = ConnectionDirection::SendOnly;
    sortable[1].status = ConnectionActivityStatus::Historical;
    sortable[1].direction = ConnectionDirection::ReceiveOnly;
    sortable[2].status = ConnectionActivityStatus::ProcessEnded;
    sortable[2].direction = ConnectionDirection::Bidirectional;
    const auto expect_first = [&](ConnectionSortColumn column, const ConnectionKey& expected) {
        auto sorted = sortable;
        SortConnectionRows(sorted, column, true);
        CHECK_EQ(sorted[0].connection.key, expected);
    };
    expect_first(ConnectionSortColumn::Status, first.key);
    expect_first(ConnectionSortColumn::Direction, first.key);
    expect_first(ConnectionSortColumn::Transport, second.key);
    expect_first(ConnectionSortColumn::ApplicationProtocol, first.key);
    expect_first(ConnectionSortColumn::LocalAddress, second.key);
    expect_first(ConnectionSortColumn::LocalPort, second.key);
    expect_first(ConnectionSortColumn::RemoteAddress, second.key);
    expect_first(ConnectionSortColumn::RemotePort, second.key);
    expect_first(ConnectionSortColumn::SentBytes, first.key);
    expect_first(ConnectionSortColumn::SentRate, second.key);
    expect_first(ConnectionSortColumn::ReceivedBytes, second.key);
    expect_first(ConnectionSortColumn::ReceivedRate, second.key);

    auto descending = rows;
    SortConnectionRows(descending, ConnectionSortColumn::SentBytes, false);
    CHECK_EQ(descending[0].connection.key, second.key);

    auto ties = BuildConnectionRows({tied, first}, true, t0);
    SortConnectionRows(ties, ConnectionSortColumn::SentBytes, true);
    CHECK_EQ(ties[0].connection.key, first.key);
    CHECK_EQ(ties[1].connection.key, tied.key);
}

void TestConnectionFilteringMatchesEndpointsAndPreservesCallerOrder() {
    const auto t0 = std::chrono::steady_clock::time_point{};
    const ConnectionDisplayRow first{
        {MakeConnectionKey({1, 1}, TransportProtocol::Tcp, ApplicationProtocol::HttpsTls,
                            50000, 443, MakeIpv4Address(192, 0, 2, 10),
                            MakeIpv4Address(198, 51, 100, 2)),
         L"first.exe", 1, 0, 0.0, 0.0, t0},
        true,
        ConnectionActivityStatus::Active,
        ConnectionDirection::SendOnly};
    const ConnectionDisplayRow second{
        {MakeConnectionKey({2, 1}, TransportProtocol::Udp, ApplicationProtocol::Dns, 5353,
                            53,
                            MakeIpv6Address({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0,
                                             0, 0, 0, 1}),
                            MakeIpv4Address(203, 0, 113, 53)),
         L"second.exe", 0, 1, 0.0, 0.0, t0},
        true,
        ConnectionActivityStatus::Historical,
        ConnectionDirection::ReceiveOnly};
    const ConnectionDisplayRow third{
        {MakeConnectionKey({3, 1}, TransportProtocol::Tcp, ApplicationProtocol::Ssh, 22, 60000,
                            MakeIpv4Address(10, 0, 0, 3),
                            MakeIpv6Address({0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0,
                                             0, 0, 0, 8})),
         L"third.exe", 1, 1, 0.0, 0.0, t0},
        true,
        ConnectionActivityStatus::Active,
        ConnectionDirection::Bidirectional};
    const std::vector<ConnectionDisplayRow> rows{first, second, third};

    const auto all = FilterConnectionRows(rows, {});
    CHECK_EQ(all.size(), 3ULL);
    if (all.size() == 3) {
        CHECK_EQ(all[0].connection.key, first.connection.key);
        CHECK_EQ(all[1].connection.key, second.connection.key);
        CHECK_EQ(all[2].connection.key, third.connection.key);
    }

    const auto local_ipv4 = FilterConnectionRows(rows, {L"192.0.2", L""});
    CHECK_EQ(local_ipv4.size(), 1ULL);
    if (local_ipv4.size() == 1) {
        CHECK_EQ(local_ipv4[0].connection.key, first.connection.key);
    }

    const auto remote_ipv4 = FilterConnectionRows(rows, {L"198.51.100", L""});
    CHECK_EQ(remote_ipv4.size(), 1ULL);
    if (remote_ipv4.size() == 1) {
        CHECK_EQ(remote_ipv4[0].connection.key, first.connection.key);
    }

    const auto case_insensitive_ipv6 = FilterConnectionRows(rows, {L"DB8", L""});
    CHECK_EQ(case_insensitive_ipv6.size(), 1ULL);
    if (case_insensitive_ipv6.size() == 1) {
        CHECK_EQ(case_insensitive_ipv6[0].connection.key, second.connection.key);
    }

    const auto both_ipv6 = FilterConnectionRows(rows, {L"2001", L""});
    CHECK_EQ(both_ipv6.size(), 2ULL);
    if (both_ipv6.size() == 2) {
        CHECK_EQ(both_ipv6[0].connection.key, second.connection.key);
        CHECK_EQ(both_ipv6[1].connection.key, third.connection.key);
    }

    const auto local_port = FilterConnectionRows(rows, {L"", L"22"});
    CHECK_EQ(local_port.size(), 1ULL);
    if (local_port.size() == 1) {
        CHECK_EQ(local_port[0].connection.key, third.connection.key);
    }

    const auto remote_port = FilterConnectionRows(rows, {L"", L"443"});
    CHECK_EQ(remote_port.size(), 1ULL);
    if (remote_port.size() == 1) {
        CHECK_EQ(remote_port[0].connection.key, first.connection.key);
    }

    const auto combined = FilterConnectionRows(rows, {L"db8", L"5353"});
    CHECK_EQ(combined.size(), 1ULL);
    if (combined.size() == 1) {
        CHECK_EQ(combined[0].connection.key, second.connection.key);
    }

    const auto mismatched_combined = FilterConnectionRows(rows, {L"db8", L"443"});
    CHECK_EQ(mismatched_combined.size(), 0ULL);
}

void TestPortFilterParsingUsesStrictDecimalPortRules() {
    const PortFilterParseResult empty = ParsePortFilter(L"");
    CHECK_EQ(empty.valid, true);
    CHECK_EQ(empty.port.has_value(), false);

    const PortFilterParseResult zero = ParsePortFilter(L"0");
    CHECK_EQ(zero.valid, true);
    CHECK_EQ(zero.port.has_value(), true);
    if (zero.port.has_value()) {
        CHECK_EQ(*zero.port, static_cast<std::uint16_t>(0));
    }

    const PortFilterParseResult maximum = ParsePortFilter(L"65535");
    CHECK_EQ(maximum.valid, true);
    CHECK_EQ(maximum.port.has_value(), true);
    if (maximum.port.has_value()) {
        CHECK_EQ(*maximum.port, static_cast<std::uint16_t>(65535));
    }

    const std::array<std::wstring_view, 8> invalid_texts{
        L" ", L" 80", L"80 ", L"+80", L"-1", L"80x", L"\uff11", L"65536"};
    for (const std::wstring_view text : invalid_texts) {
        const PortFilterParseResult result = ParsePortFilter(text);
        CHECK_EQ(result.valid, false);
        CHECK_EQ(result.port.has_value(), false);
    }
}

void TestConnectionPortFilterMatchesDisplayedPortText() {
    const auto now = std::chrono::steady_clock::now();
    const ConnectionDisplayRow row{
        {MakeConnectionKey({1, 1}, TransportProtocol::Tcp, ApplicationProtocol::Other,
                           4990, 443),
         L"server.exe", 1, 0, 0.0, 0.0, now},
        true, ConnectionActivityStatus::Active, ConnectionDirection::SendOnly};

    const auto filtered = FilterConnectionRows({row}, {L"", L" 990 "});
    CHECK_EQ(filtered.size(), 1U);
}

void TestTrafficRowsSortByCombinedSpeedAndColumnsDeterministically() {
    const TrafficKey slow{{300, 1}, TransportProtocol::Tcp, ApplicationProtocol::Http};
    const TrafficKey fast{{200, 1}, TransportProtocol::Tcp, ApplicationProtocol::Http};
    const TrafficKey medium{{100, 1}, TransportProtocol::Tcp, ApplicationProtocol::Http};
    std::vector<TrafficDisplayRow> rows{
        {MakeSnapshot(slow, L"slow.exe", 10.0, 0.0), true},
        {MakeSnapshot(fast, L"fast.exe", 30.0, 0.0), true},
        {MakeSnapshot(medium, L"medium.exe", 20.0, 0.0), true},
    };

    SortTrafficRows(rows);
    CHECK_EQ(rows[0].traffic.key.process.pid, fast.process.pid);
    CHECK_EQ(rows[1].traffic.key.process.pid, medium.process.pid);
    CHECK_EQ(rows[2].traffic.key.process.pid, slow.process.pid);

    SortTrafficRows(rows, SortColumn::Pid, true);
    CHECK_EQ(rows[0].traffic.key.process.pid, medium.process.pid);
    CHECK_EQ(rows[1].traffic.key.process.pid, fast.process.pid);
    CHECK_EQ(rows[2].traffic.key.process.pid, slow.process.pid);

    const TrafficKey first_alpha{{20, 1}, TransportProtocol::Tcp, ApplicationProtocol::Http};
    const TrafficKey second_alpha{{30, 1}, TransportProtocol::Tcp, ApplicationProtocol::Http};
    const TrafficKey bravo{{10, 1}, TransportProtocol::Tcp, ApplicationProtocol::Http};
    rows = {
        {MakeSnapshot(second_alpha, L"alpha.exe", 0.0, 0.0), true},
        {MakeSnapshot(bravo, L"bravo.exe", 0.0, 0.0), true},
        {MakeSnapshot(first_alpha, L"Alpha.exe", 0.0, 0.0), true},
    };

    SortTrafficRows(rows, SortColumn::ProcessName, true);
    CHECK_EQ(rows[0].traffic.key.process.pid, first_alpha.process.pid);
    CHECK_EQ(rows[1].traffic.key.process.pid, second_alpha.process.pid);
    CHECK_EQ(rows[2].traffic.key.process.pid, bravo.process.pid);

    const TrafficKey ended{{10, 1}, TransportProtocol::Tcp, ApplicationProtocol::Http};
    const TrafficKey first_running{{20, 1}, TransportProtocol::Tcp,
                                   ApplicationProtocol::Http};
    const TrafficKey second_running{{30, 1}, TransportProtocol::Tcp,
                                    ApplicationProtocol::Http};
    rows = {
        {MakeSnapshot(second_running, L"running-two.exe", 0.0, 0.0), true},
        {MakeSnapshot(ended, L"ended.exe", 0.0, 0.0), false},
        {MakeSnapshot(first_running, L"running-one.exe", 0.0, 0.0), true},
    };

    SortTrafficRows(rows, SortColumn::Status, false);
    CHECK_EQ(rows[0].traffic.key.process.pid, first_running.process.pid);
    CHECK_EQ(rows[1].traffic.key.process.pid, second_running.process.pid);
    CHECK_EQ(rows[2].traffic.key.process.pid, ended.process.pid);

    SortTrafficRows(rows, SortColumn::Status, true);
    CHECK_EQ(rows[0].traffic.key.process.pid, ended.process.pid);
    CHECK_EQ(rows[1].traffic.key.process.pid, first_running.process.pid);
    CHECK_EQ(rows[2].traffic.key.process.pid, second_running.process.pid);

    const TrafficKey lower_umlaut{{41, 1}, TransportProtocol::Tcp, ApplicationProtocol::Http};
    const TrafficKey upper_umlaut{{40, 1}, TransportProtocol::Tcp, ApplicationProtocol::Http};
    rows = {
        {MakeSnapshot(lower_umlaut, L"\u00e4.exe", 0.0, 0.0), true},
        {MakeSnapshot(upper_umlaut, L"\u00c4.exe", 0.0, 0.0), true},
    };
    SortTrafficRows(rows, SortColumn::ProcessName, true);
    CHECK_EQ(rows[0].traffic.key.process.pid, upper_umlaut.process.pid);
    CHECK_EQ(rows[1].traffic.key.process.pid, lower_umlaut.process.pid);
}

void TestVisibleRowsFilterWithoutMutatingSnapshotAndAttachLiveness() {
    const TrafficKey fast_alpha{{101, 11}, TransportProtocol::Tcp,
                                ApplicationProtocol::HttpsTls};
    const TrafficKey slow_alpha{{102, 22}, TransportProtocol::Udp,
                                ApplicationProtocol::Dns};
    const TrafficKey beta{{103, 33}, TransportProtocol::Tcp,
                          ApplicationProtocol::Http};
    const std::vector<TrafficSnapshot> snapshots{
        MakeSnapshot(slow_alpha, L"AlphaWorker.exe", 2.0, 3.0),
        MakeSnapshot(beta, L"beta.exe", 100.0, 100.0),
        MakeSnapshot(fast_alpha, L"ALPHA.exe", 20.0, 30.0),
    };

    const auto rows = BuildVisibleRows(
        snapshots, L"alpha", SortColumn::CombinedSpeed, false,
        [](ProcessInstanceId process) { return process.pid == 102; });

    CHECK_EQ(rows.size(), 2U);
    CHECK_EQ(rows[0].traffic.key.process.pid, fast_alpha.process.pid);
    CHECK_EQ(rows[1].traffic.key.process.pid, slow_alpha.process.pid);
    CHECK_EQ(ProcessStatusText(rows[0].process_alive), L"已结束");
    CHECK_EQ(ProcessStatusText(rows[1].process_alive), L"运行中");
    CHECK_EQ(snapshots.size(), 3U);
    CHECK_EQ(snapshots[1].process_name, L"beta.exe");
}

void TestProcessRateTotalsSumEveryCapturedProcess() {
    const std::array snapshots{
        MakeSnapshot({{1, 1}, TransportProtocol::Tcp, ApplicationProtocol::Http},
                     L"first.exe", 100.0, 25.0),
        MakeSnapshot({{2, 2}, TransportProtocol::Udp, ApplicationProtocol::Dns},
                     L"second.exe", 50.0, 75.0)};

    const auto totals = SumTrafficRates(snapshots);
    CHECK_EQ(totals.sent_bytes_per_second, 150.0);
    CHECK_EQ(totals.received_bytes_per_second, 100.0);
}

void TestVisibleRowsDefaultOrderUsesCombinedSpeedDescending() {
    const TrafficKey slow{{201, 11}, TransportProtocol::Tcp, ApplicationProtocol::Http};
    const TrafficKey fast{{202, 22}, TransportProtocol::Udp, ApplicationProtocol::Dns};
    const TrafficKey medium{{203, 33}, TransportProtocol::Tcp,
                            ApplicationProtocol::HttpsTls};
    const std::vector<TrafficSnapshot> snapshots{
        MakeSnapshot(slow, L"slow.exe", 1.0, 2.0),
        MakeSnapshot(fast, L"fast.exe", 30.0, 20.0),
        MakeSnapshot(medium, L"medium.exe", 10.0, 10.0),
    };

    const auto rows = BuildVisibleRows(
        snapshots, L"", SortColumn::CombinedSpeed, false,
        [](ProcessInstanceId) { return true; });

    CHECK_EQ(rows.size(), 3U);
    CHECK_EQ(rows[0].traffic.key.process.pid, fast.process.pid);
    CHECK_EQ(rows[1].traffic.key.process.pid, medium.process.pid);
    CHECK_EQ(rows[2].traffic.key.process.pid, slow.process.pid);
}

void TestVisibleRowsUsesInvariantUnicodeCaseInsensitiveFilter() {
    const TrafficKey process{{301, 44}, TransportProtocol::Tcp,
                             ApplicationProtocol::HttpsTls};
    const std::vector<TrafficSnapshot> snapshots{
        MakeSnapshot(process, L"Äther.exe", 1.0, 1.0),
    };

    const auto rows = BuildVisibleRows(
        snapshots, L"äTHER", SortColumn::CombinedSpeed, false,
        [](ProcessInstanceId) { return true; });

    CHECK_EQ(rows.size(), 1U);
    CHECK_EQ(rows[0].traffic.key.process.pid, process.process.pid);
}

void TestProcessForVisibleRowReturnsProcessInstanceIdentity() {
    const ProcessInstanceId first_process{401, 55};
    const ProcessInstanceId reused_pid{401, 66};
    const std::vector<TrafficKey> current_keys{
        {first_process, TransportProtocol::Tcp, ApplicationProtocol::HttpsTls},
        {first_process, TransportProtocol::Udp, ApplicationProtocol::Quic},
        {reused_pid, TransportProtocol::Tcp, ApplicationProtocol::Http},
    };

    const auto first = ProcessForVisibleRow(current_keys, 0);
    const auto second_protocol = ProcessForVisibleRow(current_keys, 1);
    const auto reused = ProcessForVisibleRow(current_keys, 2);
    CHECK_EQ(first.has_value(), true);
    CHECK_EQ(second_protocol.has_value(), true);
    CHECK_EQ(reused.has_value(), true);
    if (first && second_protocol && reused) {
        CHECK_EQ(first->pid, second_protocol->pid);
        CHECK_EQ(first->creation_time_100ns, second_protocol->creation_time_100ns);
        CHECK_EQ(first->pid, reused->pid);
        CHECK_EQ(first->creation_time_100ns == reused->creation_time_100ns, false);
    }
    CHECK_EQ(ProcessForVisibleRow(current_keys, -1).has_value(), false);
    CHECK_EQ(ProcessForVisibleRow(current_keys, 3).has_value(), false);
}

void TestConnectionWindowRegistryErasesOnlyMatchingHandle() {
    const ProcessInstanceId first_process{501, 77};
    const ProcessInstanceId second_process{502, 88};
    const HWND first_window =
        reinterpret_cast<HWND>(static_cast<std::uintptr_t>(0x101));
    const HWND second_window =
        reinterpret_cast<HWND>(static_cast<std::uintptr_t>(0x202));
    const HWND unrelated_window =
        reinterpret_cast<HWND>(static_cast<std::uintptr_t>(0x303));
    std::map<ProcessInstanceId, HWND> registry{
        {first_process, first_window},
        {second_process, second_window},
    };

    CHECK_EQ(EraseConnectionWindowIfMatches(registry, unrelated_window), false);
    CHECK_EQ(registry.size(), 2U);
    CHECK_EQ(EraseConnectionWindowIfMatches(registry, first_window), true);
    CHECK_EQ(registry.size(), 1U);
    CHECK_EQ(registry.contains(first_process), false);
    CHECK_EQ(registry.contains(second_process), true);
    if (registry.contains(second_process)) {
        CHECK_EQ(registry.at(second_process), second_window);
    }
}

void TestTakeConnectionWindowsMakesDestroyCallbacksSafe() {
    const ProcessInstanceId process{503, 99};
    const HWND window =
        reinterpret_cast<HWND>(static_cast<std::uintptr_t>(0x404));
    std::map<ProcessInstanceId, HWND> registry{{process, window}};

    const auto windows_to_destroy = TakeConnectionWindows(registry);
    CHECK_EQ(registry.empty(), true);
    CHECK_EQ(windows_to_destroy.size(), 1U);
    CHECK_EQ(EraseConnectionWindowIfMatches(registry, window), false);
    CHECK_EQ(registry.empty(), true);
    CHECK_EQ(windows_to_destroy.at(process), window);
}

void TestProcessInfoResolvesLiveAndInaccessibleProcesses() {
    ProcessInfoCache cache;

    const auto current_process = cache.Resolve(GetCurrentProcessId(), 0);
    CHECK_EQ(current_process.id.pid, GetCurrentProcessId());
    CHECK_EQ(current_process.name.empty(), false);
    CHECK_EQ(current_process.id.creation_time_100ns == 0, false);
    CHECK_EQ(current_process.alive, true);
    CHECK_EQ(cache.RefreshAlive(current_process.id), true);
    const ProcessInstanceId wrong_creation_time{current_process.id.pid,
                                                current_process.id.creation_time_100ns + 1};
    CHECK_EQ(cache.RefreshAlive(wrong_creation_time), false);

    constexpr std::uint32_t inaccessible_pid = 0xFFFFFFFFu;
    const auto inaccessible_process = cache.Resolve(inaccessible_pid, 42);
    CHECK_EQ(inaccessible_process.id.pid, inaccessible_pid);
    CHECK_EQ(inaccessible_process.name, L"受限进程 (4294967295)");
    CHECK_EQ(inaccessible_process.id.creation_time_100ns, 42ULL);
    CHECK_EQ(inaccessible_process.alive, false);
    CHECK_EQ(cache.RefreshAlive(inaccessible_process.id), false);

    const auto same_inaccessible_process = cache.Resolve(inaccessible_pid, 84);
    CHECK_EQ(same_inaccessible_process.id.creation_time_100ns, 42ULL);
}

void TestProcessInfoFallbackDoesNotMaskRealIdentityOrPidReuse() {
    constexpr std::uint32_t pid = 1234;
    FakeProcessInfoApi api;
    api.query_results = {
        std::nullopt,
        ProcessInfo{{pid, 500}, L"first.exe", true},
        ProcessInfo{{pid, 600}, L"second.exe", true},
    };
    ProcessInfoCache cache(api);

    const auto fallback = cache.Resolve(pid, 100);
    for (std::uint64_t observation = 101; observation < 108; ++observation) {
        CHECK_EQ(cache.Resolve(pid, observation).id.creation_time_100ns, 100ULL);
    }
    const auto first_real_process = cache.Resolve(pid, 108);
    api.creation_time = 600;
    const auto reused_pid_process = cache.Resolve(pid, 109);

    CHECK_EQ(fallback.id.creation_time_100ns, 100ULL);
    CHECK_EQ(first_real_process.id.creation_time_100ns, 500ULL);
    CHECK_EQ(first_real_process.name, L"first.exe");
    CHECK_EQ(reused_pid_process.id.creation_time_100ns, 600ULL);
    CHECK_EQ(reused_pid_process.name, L"second.exe");
}

void TestProcessInfoCacheUsesCreationTimeOnRealCacheHits() {
    constexpr std::uint32_t pid = 4321;
    FakeProcessInfoApi api;
    api.query_results = {ProcessInfo{{pid, 500}, L"first.exe", true}};
    api.creation_time = 500;
    ProcessInfoCache cache(api);

    for (std::uint64_t observation = 1; observation <= 5; ++observation) {
        CHECK_EQ(cache.Resolve(pid, observation).name, L"first.exe");
    }

    CHECK_EQ(api.query_process_calls, 1);
    CHECK_EQ(api.query_creation_time_calls, 4);
}

void TestProcessInfoFallbackDetectsAccessiblePidReuseWithinEightEvents() {
    constexpr std::uint32_t pid = 4322;
    FakeProcessInfoApi api;
    api.query_results = {
        std::nullopt,
        ProcessInfo{{pid, 700}, L"recovered.exe", true},
    };
    ProcessInfoCache cache(api);

    CHECK_EQ(cache.Resolve(pid, 1).alive, false);
    for (std::uint64_t observation = 2; observation < 9; ++observation) {
        CHECK_EQ(cache.Resolve(pid, observation).alive, false);
    }
    CHECK_EQ(api.query_process_calls, 1);
    const auto reused = cache.Resolve(pid, 9);
    CHECK_EQ(reused.name, L"recovered.exe");
    CHECK_EQ(reused.id.creation_time_100ns, 700ULL);
    CHECK_EQ(api.query_process_calls, 2);
}

void TestProcessInfoCreationQueryFailureEventuallyDetectsPidReuse() {
    constexpr std::uint32_t pid = 4323;
    FakeProcessInfoApi api;
    api.query_results = {
        ProcessInfo{{pid, 800}, L"old.exe", true},
        ProcessInfo{{pid, 900}, L"new.exe", true},
    };
    api.creation_time_results.assign(8, std::nullopt);
    ProcessInfoCache cache(api);

    CHECK_EQ(cache.Resolve(pid, 1).name, L"old.exe");
    for (std::uint64_t observation = 2; observation < 9; ++observation) {
        CHECK_EQ(cache.Resolve(pid, observation).name, L"old.exe");
    }
    CHECK_EQ(cache.Resolve(pid, 9).name, L"new.exe");
    CHECK_EQ(api.query_process_calls, 2);
    CHECK_EQ(api.query_creation_time_calls, 8);
}

void TestSingleInstanceGuardRejectsSecondOwnerAndReleasesName() {
    const std::wstring name = L"Local\\NetAssessTests-" +
                              std::to_wstring(GetCurrentProcessId()) + L"-single-instance";
    {
        SingleInstanceGuard first(name);
        CHECK_EQ(first.acquired(), true);
        CHECK_EQ(first.error(), static_cast<DWORD>(ERROR_SUCCESS));

        SingleInstanceGuard second(name);
        CHECK_EQ(second.acquired(), false);
        CHECK_EQ(second.error(), static_cast<DWORD>(ERROR_ALREADY_EXISTS));
    }

    SingleInstanceGuard after_release(name);
    CHECK_EQ(after_release.acquired(), true);
}

void TestEtwMonitorStartsOneConfiguredConsumer() {
    TrafficAggregator aggregator;
    ConnectionAggregator connection_aggregator;
    ProcessInfoCache process_cache;
    FakeEtwSessionApi api;
    EtwMonitor monitor(aggregator, connection_aggregator, process_cache, api);

    CHECK_EQ(monitor.Start(), true);
    CHECK_EQ(api.WaitForConsumers(), true);
    CHECK_EQ(monitor.running(), true);
    CHECK_EQ(api.start_trace_calls, 1);
    CHECK_EQ(api.open_trace_calls, 1);
    CHECK_EQ(api.process_trace_calls, 1);
    CHECK_EQ(api.started_name, L"NetAssess-Kernel-Network");
    CHECK_EQ(api.opened_name, api.started_name);
    CHECK_EQ(IsEqualGUID(api.properties_guid, GUID_NULL), FALSE);
    CHECK_EQ(api.properties_flags, static_cast<ULONG>(WNODE_FLAG_TRACED_GUID));
    CHECK_EQ(api.client_context, 1UL);
    CHECK_EQ(api.log_file_mode,
             static_cast<ULONG>(EVENT_TRACE_REAL_TIME_MODE |
                                EVENT_TRACE_SYSTEM_LOGGER_MODE));
    CHECK_EQ(api.enable_flags, static_cast<ULONG>(EVENT_TRACE_FLAG_NETWORK_TCPIP));
    CHECK_EQ(api.open_mode,
             static_cast<ULONG>(PROCESS_TRACE_MODE_REAL_TIME |
                                PROCESS_TRACE_MODE_EVENT_RECORD));
    CHECK_EQ(api.opened_context, static_cast<void*>(&monitor));
    CHECK_EQ(api.has_event_callback, true);

    CHECK_EQ(monitor.Start(), true);
    CHECK_EQ(api.start_trace_calls, 1);
    CHECK_EQ(api.open_trace_calls, 1);
    CHECK_EQ(api.process_trace_calls, 1);
    monitor.Stop();
}

void TestEtwMonitorStopsOnlyOwnedResourcesAndStopIsIdempotent() {
    TrafficAggregator aggregator;
    ConnectionAggregator connection_aggregator;
    ProcessInfoCache process_cache;
    FakeEtwSessionApi api;
    EtwMonitor monitor(aggregator, connection_aggregator, process_cache, api);

    CHECK_EQ(monitor.Start(), true);
    CHECK_EQ(api.WaitForConsumers(), true);
    monitor.Stop();

    CHECK_EQ(monitor.running(), false);
    CHECK_EQ(api.control_stop_calls, 1);
    CHECK_EQ(api.controlled_session_handle, api.session_handle_to_return);
    CHECK_EQ(api.controlled_name, api.started_name);
    CHECK_EQ(api.controlled_code, static_cast<ULONG>(EVENT_TRACE_CONTROL_STOP));
    CHECK_EQ(api.close_trace_calls, 1);
    CHECK_EQ(api.closed_trace_handle, api.trace_handle_to_return);
    CHECK_EQ(api.calls[api.calls.size() - 2], std::string("control-stop"));
    CHECK_EQ(api.calls[api.calls.size() - 1], std::string("close"));

    monitor.Stop();
    CHECK_EQ(api.control_stop_calls, 1);
    CHECK_EQ(api.close_trace_calls, 1);
}

void TestEtwMonitorExposesStartTraceFailureWithoutOpeningConsumer() {
    TrafficAggregator aggregator;
    ConnectionAggregator connection_aggregator;
    ProcessInfoCache process_cache;
    FakeEtwSessionApi api;
    api.start_status = ERROR_ACCESS_DENIED;
    EtwMonitor monitor(aggregator, connection_aggregator, process_cache, api);

    CHECK_EQ(monitor.Start(), false);
    CHECK_EQ(monitor.running(), false);
    CHECK_EQ(monitor.last_error(), static_cast<ULONG>(ERROR_ACCESS_DENIED));
    CHECK_EQ(api.start_trace_calls, 1);
    CHECK_EQ(api.open_trace_calls, 0);
    CHECK_EQ(api.process_trace_calls, 0);
    CHECK_EQ(api.control_stop_calls, 0);
    CHECK_EQ(api.close_trace_calls, 0);
}

void TestEtwMonitorCleansOnlyLegacyNetAssessSessionsAndRetriesResourceFailure() {
    TrafficAggregator aggregator;
    ConnectionAggregator connection_aggregator;
    ProcessInfoCache process_cache;
    FakeEtwSessionApi api;
    api.start_statuses = {ERROR_NO_SYSTEM_RESOURCES, ERROR_SUCCESS};
    api.active_session_names = {
        L"NetAssess-1234-{01234567-89AB-CDEF-0123-456789ABCDEF}",
        L"Other-Monitor",
        L"NetAssess-not-a-legacy-session"};
    EtwMonitor monitor(aggregator, connection_aggregator, process_cache, api);

    CHECK_EQ(monitor.Start(), true);
    CHECK_EQ(api.WaitForConsumers(), true);
    CHECK_EQ(api.start_trace_calls, 2);
    CHECK_EQ(api.query_all_calls, 1);
    CHECK_EQ(api.stopped_names.size(), 1U);
    if (!api.stopped_names.empty()) {
        CHECK_EQ(api.stopped_names[0], api.active_session_names[0]);
    }
    monitor.Stop();
}

void TestEtwMonitorCleansOwnedSessionWhenOpenTraceFails() {
    TrafficAggregator aggregator;
    ConnectionAggregator connection_aggregator;
    ProcessInfoCache process_cache;
    FakeEtwSessionApi api;
    api.open_error = ERROR_BAD_LENGTH;
    api.trace_handle_to_return = INVALID_PROCESSTRACE_HANDLE;
    EtwMonitor monitor(aggregator, connection_aggregator, process_cache, api);

    CHECK_EQ(monitor.Start(), false);
    CHECK_EQ(monitor.running(), false);
    CHECK_EQ(monitor.last_error(), static_cast<ULONG>(ERROR_BAD_LENGTH));
    CHECK_EQ(api.start_trace_calls, 1);
    CHECK_EQ(api.open_trace_calls, 1);
    CHECK_EQ(api.process_trace_calls, 0);
    CHECK_EQ(api.control_stop_calls, 1);
    CHECK_EQ(api.controlled_session_handle, api.session_handle_to_return);
    CHECK_EQ(api.controlled_name, api.started_name);
    CHECK_EQ(api.close_trace_calls, 0);

    monitor.Stop();
    CHECK_EQ(api.control_stop_calls, 1);
    CHECK_EQ(api.close_trace_calls, 0);
}

void TestEtwMonitorCleansOwnedResourcesWhenConsumerFails() {
    TrafficAggregator aggregator;
    ConnectionAggregator connection_aggregator;
    ProcessInfoCache process_cache;
    FakeEtwSessionApi api;
    api.block_process_trace = false;
    api.process_status = ERROR_BAD_LENGTH;
    EtwMonitor monitor(aggregator, connection_aggregator, process_cache, api);

    CHECK_EQ(monitor.Start(), true);
    CHECK_EQ(api.WaitForClose(), true);
    CHECK_EQ(monitor.running(), false);
    CHECK_EQ(monitor.last_error(), static_cast<ULONG>(ERROR_BAD_LENGTH));
    CHECK_EQ(api.control_stop_calls, 1);
    CHECK_EQ(api.close_trace_calls, 1);

    monitor.Stop();
    CHECK_EQ(api.control_stop_calls, 1);
    CHECK_EQ(api.close_trace_calls, 1);
}

void TestEtwMonitorDoesNotReportSuccessfulPendingStopCodesAsErrors() {
    for (const ULONG stop_status : {ERROR_MORE_DATA, ERROR_ACTIVE_CONNECTIONS}) {
        TrafficAggregator aggregator;
        ConnectionAggregator connection_aggregator;
        ProcessInfoCache process_cache;
        FakeEtwSessionApi api;
        api.control_status = stop_status;
        api.close_status = ERROR_CTX_CLOSE_PENDING;
        EtwMonitor monitor(aggregator, connection_aggregator, process_cache, api);

        CHECK_EQ(monitor.Start(), true);
        CHECK_EQ(api.WaitForConsumers(), true);
        monitor.Stop();

        CHECK_EQ(monitor.last_error(), static_cast<ULONG>(ERROR_SUCCESS));
    }
}

void TestEtwMonitorStopPublishesStateOnlyAfterTransitionLock() {
    TrafficAggregator traffic;
    ConnectionAggregator connections;
    ProcessInfoCache cache;
    FakeEtwSessionApi api;
    api.block_query = true;
    EtwMonitor monitor(traffic, connections, cache, api);
    CHECK_EQ(monitor.Start(), true);
    CHECK_EQ(api.WaitForConsumers(), true);
    std::jthread query([&] { monitor.loss_counters(); });
    CHECK_EQ(api.WaitForQuery(), true);
    std::atomic_bool entered{};
    std::jthread stop([&] { entered = true; monitor.Stop(); });
    while (!entered.load()) { std::this_thread::yield(); }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
    while (monitor.running() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::yield();
    }
    // A blocked external Stop must not invite Start to join an unsignalled consumer.
    CHECK_EQ(monitor.running(), true);
    api.ReleaseQuery();
    query.join();
    stop.join();
    CHECK_EQ(monitor.Start(), true);
    monitor.Stop();
}

void TestEtwMonitorBadLengthStopReleasesOwnershipButRetainsValidCounters() {
    TrafficAggregator traffic;
    ConnectionAggregator connections;
    ProcessInfoCache cache;
    FakeEtwSessionApi api;
    api.query_events_lost = 5;
    api.query_real_time_buffers_lost = 7;
    api.stop_events_lost = 99;
    api.stop_real_time_buffers_lost = 101;
    api.control_status = ERROR_BAD_LENGTH;
    EtwMonitor monitor(traffic, connections, cache, api);
    CHECK_EQ(monitor.Start(), true);
    CHECK_EQ(api.WaitForConsumers(), true);
    CHECK_EQ(monitor.loss_counters().events_lost, 5ULL);
    monitor.Stop();
    CHECK_EQ(monitor.last_error(), static_cast<ULONG>(ERROR_SUCCESS));
    const auto loss = monitor.loss_counters();
    CHECK_EQ(loss.events_lost, 5ULL);
    CHECK_EQ(loss.real_time_buffers_lost, 7ULL);
    CHECK_EQ(monitor.Start(), true);
    monitor.Stop();
}

void TestMainWindowRetriesFailedStopInsteadOfStartingAnotherSession() {
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES};
    CHECK_EQ(InitCommonControlsEx(&controls), TRUE);
    TrafficAggregator traffic;
    ConnectionAggregator connections;
    ProcessInfoCache cache;
    FakeEtwSessionApi api;
    api.control_stop_statuses = {ERROR_ACCESS_DENIED, ERROR_SUCCESS};
    api.query_status = ERROR_INVALID_DATA;
    EtwMonitor monitor(traffic, connections, cache, api);
    HWND window = CreateMainWindow(GetModuleHandleW(nullptr), traffic, connections, cache, monitor);
    CHECK_EQ(window != nullptr, true);
    if (window == nullptr) { return; }
    CHECK_EQ(StartMainWindowCollection(window), true);
    CHECK_EQ(api.WaitForConsumers(), true);
    SendMessageW(window, WM_COMMAND, MAKEWPARAM(1001, BN_CLICKED), 0);
    CHECK_EQ(monitor.last_error(), static_cast<ULONG>(ERROR_ACCESS_DENIED));
    SendMessageW(window, WM_COMMAND, MAKEWPARAM(1001, BN_CLICKED), 0);
    CHECK_EQ(api.control_stop_calls, 2);
    CHECK_EQ(api.start_trace_calls, 1);
    SendMessageW(window, WM_COMMAND, MAKEWPARAM(1001, BN_CLICKED), 0);
    CHECK_EQ(api.start_trace_calls, 2);
    CHECK_EQ(monitor.running(), true);
    DestroyWindow(window);
    MSG message{};
    while (PeekMessageW(&message, nullptr, WM_QUIT, WM_QUIT, PM_REMOVE)) {}
}

void TestMainWindowExplainsEtwLoggerExhaustion() {
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES};
    CHECK_EQ(InitCommonControlsEx(&controls), TRUE);
    TrafficAggregator traffic;
    ConnectionAggregator connections;
    ProcessInfoCache cache;
    FakeEtwSessionApi api;
    api.start_status = ERROR_NO_SYSTEM_RESOURCES;
    EtwMonitor monitor(traffic, connections, cache, api);
    HWND window = CreateMainWindow(GetModuleHandleW(nullptr), traffic, connections, cache, monitor);
    CHECK_EQ(window != nullptr, true);
    if (window == nullptr) { return; }

    CHECK_EQ(StartMainWindowCollection(window), false);
    HWND status = FindWindowExW(window, nullptr, STATUSCLASSNAMEW, nullptr);
    std::wstring text(512, L'\0');
    SendMessageW(status, SB_GETTEXTW, 0, reinterpret_cast<LPARAM>(text.data()));
    text.resize(std::wcslen(text.c_str()));
    CHECK_EQ(text.find(L"ETW 系统记录器名额已满") != std::wstring::npos, true);
    DestroyWindow(window);
}

int main_list_destroy_notifications = 0;

LRESULT CALLBACK ObserveMainListDestruction(HWND list, UINT message, WPARAM wparam,
                                            LPARAM lparam, UINT_PTR subclass_id,
                                            DWORD_PTR) {
    if (message == WM_NCDESTROY) {
        ++main_list_destroy_notifications;
        RemoveWindowSubclass(list, ObserveMainListDestruction, subclass_id);
    }
    return DefSubclassProc(list, message, wparam, lparam);
}

void TestMainWindowCreatesOperationalToolbarAndSortArrow() {
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES};
    CHECK_EQ(InitCommonControlsEx(&controls), TRUE);
    TrafficAggregator traffic;
    ConnectionAggregator connections;
    ProcessInfoCache cache;
    FakeEtwSessionApi api;
    EtwMonitor monitor(traffic, connections, cache, api);
    HWND window = CreateMainWindow(GetModuleHandleW(nullptr), traffic, connections, cache, monitor);
    CHECK_EQ(window != nullptr, true);
    if (window == nullptr) { return; }
    HWND export_button = nullptr;
    HWND list = nullptr;
    for (HWND child = GetWindow(window, GW_CHILD); child != nullptr;
         child = GetWindow(child, GW_HWNDNEXT)) {
        wchar_t title[32]{};
        wchar_t class_name[32]{};
        GetWindowTextW(child, title, static_cast<int>(std::size(title)));
        GetClassNameW(child, class_name, static_cast<int>(std::size(class_name)));
        if (std::wstring_view(title) == L"导出 CSV") { export_button = child; }
        if (std::wstring_view(class_name) == WC_LISTVIEWW) { list = child; }
    }
    CHECK_EQ(export_button != nullptr, true);
    CHECK_EQ(list != nullptr, true);
    MINMAXINFO limits{};
    SendMessageW(window, WM_GETMINMAXINFO, 0, reinterpret_cast<LPARAM>(&limits));
    CHECK_EQ(limits.ptMinTrackSize.x > 0, true);
    CHECK_EQ(limits.ptMinTrackSize.y > 0, true);
    RECT suggested{100, 100, 1240, 730};
    SendMessageW(window, WM_DPICHANGED, MAKEWPARAM(144, 144),
                 reinterpret_cast<LPARAM>(&suggested));
    SendMessageW(window, WM_GETMINMAXINFO, 0, reinterpret_cast<LPARAM>(&limits));
    CHECK_EQ(limits.ptMinTrackSize.x, 1140);
    CHECK_EQ(limits.ptMinTrackSize.y, 630);
    RECT client{};
    GetClientRect(window, &client);
    HWND clear_button = GetDlgItem(window, 1002);
    HWND filter = GetDlgItem(window, 1003);
    CHECK_EQ(clear_button != nullptr && filter != nullptr, true);
    if (clear_button != nullptr && export_button != nullptr && filter != nullptr) {
        RECT clear_bounds{};
        RECT export_bounds{};
        RECT filter_bounds{};
        GetWindowRect(clear_button, &clear_bounds);
        GetWindowRect(export_button, &export_bounds);
        GetWindowRect(filter, &filter_bounds);
        MapWindowPoints(nullptr, window, reinterpret_cast<POINT*>(&clear_bounds), 2);
        MapWindowPoints(nullptr, window, reinterpret_cast<POINT*>(&export_bounds), 2);
        MapWindowPoints(nullptr, window, reinterpret_cast<POINT*>(&filter_bounds), 2);
        CHECK_EQ(clear_bounds.right <= export_bounds.left, true);
        CHECK_EQ(export_bounds.right <= filter_bounds.left, true);
        CHECK_EQ(filter_bounds.right <= client.right, true);
        CHECK_EQ(filter_bounds.right > filter_bounds.left, true);
    }
    if (list != nullptr) {
        CHECK_EQ(ListView_GetColumnWidth(list, 0), 285);
        main_list_destroy_notifications = 0;
        CHECK_EQ(SetWindowSubclass(list, ObserveMainListDestruction, 99, 0) != FALSE, true);
        HWND header = ListView_GetHeader(list);
        HDITEMW item{};
        item.mask = HDI_FORMAT;
        for (int column = 0; column < 9; ++column) {
            CHECK_EQ(Header_GetItem(header, column, &item) != FALSE, true);
            CHECK_EQ((item.fmt & (HDF_SORTUP | HDF_SORTDOWN)) == 0, true);
        }
        NMLISTVIEW click{};
        click.hdr.hwndFrom = list;
        click.hdr.code = LVN_COLUMNCLICK;
        click.iSubItem = 1;
        SendMessageW(window, WM_NOTIFY, 0, reinterpret_cast<LPARAM>(&click));
        CHECK_EQ(Header_GetItem(header, 1, &item) != FALSE, true);
        CHECK_EQ((item.fmt & HDF_SORTUP) != 0, true);
    }
    DestroyWindow(window);
    CHECK_EQ(IsWindow(window), FALSE);
    if (list != nullptr) {
        CHECK_EQ(main_list_destroy_notifications, 1);
        CHECK_EQ(IsWindow(list), FALSE);
    }
    MSG message{};
    while (PeekMessageW(&message, nullptr, WM_QUIT, WM_QUIT, PM_REMOVE)) {}
}

int main_menu_command = 0;
std::vector<std::wstring> main_menu_labels;
bool main_confirm_result = false;
int main_confirm_calls = 0;
std::wstring main_confirm_name;
ProcessInstanceId main_confirm_process;
int main_error_calls = 0;
std::wstring main_error_action;
DWORD main_error_code = ERROR_SUCCESS;
std::vector<std::wstring> main_csv_headers;
std::vector<std::vector<std::wstring>> main_csv_rows;
CsvSaveResult main_csv_result{false, ERROR_SUCCESS};
TrafficAggregator* main_reorder_traffic = nullptr;
int main_menu_refreshes = 0;
int main_confirmation_refreshes = 0;
int ChooseMainMenu(HWND, HMENU, POINT);
bool ConfirmMainTerminate(HWND, std::wstring_view, ProcessInstanceId);

int ChooseMainMenuAfterRefresh(HWND owner, HMENU menu, POINT point) {
    const int command = ChooseMainMenu(owner, menu, point);
    ++main_menu_refreshes;
    main_reorder_traffic->Add({{{4001, 91}, TransportProtocol::Tcp,
                                ApplicationProtocol::Http},
                               L"aaa.exe", TrafficDirection::Send, 1});
    SendMessageW(owner, WM_TIMER, 1, 0);
    return command;
}

bool ConfirmMainTerminateAfterRefresh(HWND owner, std::wstring_view name,
                                      ProcessInstanceId process) {
    ConfirmMainTerminate(owner, name, process);
    ++main_confirmation_refreshes;
    main_reorder_traffic->Add({{{4002, 92}, TransportProtocol::Tcp,
                                ApplicationProtocol::Http},
                               L"aab.exe", TrafficDirection::Send, 1});
    SendMessageW(owner, WM_TIMER, 1, 0);
    return main_confirm_result;
}

int ChooseMainMenu(HWND, HMENU menu, POINT) {
    main_menu_labels.clear();
    for (int index = 0; index < GetMenuItemCount(menu); ++index) {
        wchar_t text[64]{};
        GetMenuStringW(menu, index, text, static_cast<int>(std::size(text)), MF_BYPOSITION);
        main_menu_labels.emplace_back(text);
    }
    return main_menu_command;
}

bool ConfirmMainTerminate(HWND, std::wstring_view name, ProcessInstanceId process) {
    ++main_confirm_calls;
    main_confirm_name = name;
    main_confirm_process = process;
    return main_confirm_result;
}

void CaptureMainError(HWND, std::wstring_view action, DWORD code) {
    ++main_error_calls;
    main_error_action = action;
    main_error_code = code;
}

CsvSaveResult CaptureMainCsv(HWND, std::wstring_view,
                             std::span<const std::wstring> headers,
                             std::span<const std::vector<std::wstring>> rows) {
    main_csv_headers.assign(headers.begin(), headers.end());
    main_csv_rows.assign(rows.begin(), rows.end());
    return main_csv_result;
}

void TestMainWindowRoutesProcessActionsAndExportsVisibleRows() {
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES};
    CHECK_EQ(InitCommonControlsEx(&controls), TRUE);
    TrafficAggregator traffic;
    ConnectionAggregator connections;
    ProcessInfoCache cache;
    FakeEtwSessionApi etw_api;
    EtwMonitor etw(traffic, connections, cache, etw_api);
    FakeProcessActionApi action_api;
    action_api.creation_time_100ns = 77;
    ProcessActions actions(action_api);
    traffic.Add({{{4242, 77}, TransportProtocol::Tcp, ApplicationProtocol::HttpsTls},
                 L"zeta.exe", TrafficDirection::Send, 1024});
    traffic.Add({{{4243, 88}, TransportProtocol::Udp, ApplicationProtocol::Dns},
                 L"alpha.exe", TrafficDirection::Receive, 2048});
    MainWindowDependencies dependencies{};
    dependencies.process_actions = &actions;
    dependencies.choose_menu_command = ChooseMainMenu;
    dependencies.confirm_termination = ConfirmMainTerminate;
    dependencies.present_error = CaptureMainError;
    dependencies.save_csv = CaptureMainCsv;
    HWND window = CreateMainWindow(GetModuleHandleW(nullptr), traffic, connections,
                                   cache, etw, dependencies);
    CHECK_EQ(window != nullptr, true);
    if (window == nullptr) { return; }
    HWND list = FindWindowExW(window, nullptr, WC_LISTVIEWW, nullptr);
    CHECK_EQ(list != nullptr, true);
    HWND filter = GetDlgItem(window, 1003);
    CHECK_EQ(filter != nullptr, true);
    if (list != nullptr && filter != nullptr) {
        NMLISTVIEW sort_click{};
        sort_click.hdr.hwndFrom = list;
        sort_click.hdr.code = LVN_COLUMNCLICK;
        sort_click.iSubItem = 0;
        SendMessageW(window, WM_NOTIFY, 0, reinterpret_cast<LPARAM>(&sort_click));
        SendMessageW(window, WM_COMMAND, MAKEWPARAM(1005, BN_CLICKED), 0);
        CHECK_EQ(main_csv_rows.size(), 2U);
        if (main_csv_rows.size() == 2) {
            CHECK_EQ(main_csv_rows[0][0], L"alpha.exe");
            CHECK_EQ(main_csv_rows[1][0], L"zeta.exe");
        }
        SetWindowTextW(filter, L"zeta");
        CHECK_EQ(ListView_GetItemCount(list), 1);
        main_csv_headers.clear();
        main_csv_rows.clear();
        SendMessageW(window, WM_COMMAND, MAKEWPARAM(1005, BN_CLICKED), 0);
        CHECK_EQ(main_csv_headers.size(), 9U);
        CHECK_EQ(main_csv_rows.size(), 1U);
        if (main_csv_rows.size() == 1) {
            CHECK_EQ(main_csv_rows[0].size(), 9U);
            const std::array<std::wstring_view, 9> expected_headers{
                L"进程名", L"PID", L"状态", L"传输层协议", L"推断应用协议",
                L"上行累计", L"上行速度", L"下行累计", L"下行速度"};
            const std::array<std::wstring_view, 9> expected_cells{
                L"zeta.exe", L"4242", L"已结束", L"TCP", L"HTTPS/TLS（端口推断）",
                L"1 KB", L"0 B/s", L"0 B", L"0 B/s"};
            for (int column = 0; column < 9; ++column) {
                CHECK_EQ(main_csv_headers[column], expected_headers[column]);
                CHECK_EQ(main_csv_rows[0][column], expected_cells[column]);
                wchar_t displayed[256]{};
                ListView_GetItemText(list, 0, column, displayed,
                                     static_cast<int>(std::size(displayed)));
                CHECK_EQ(main_csv_rows[0][column], std::wstring_view(displayed));
            }
        }
        main_csv_result = {false, ERROR_ACCESS_DENIED};
        main_error_calls = 0;
        SendMessageW(window, WM_COMMAND, MAKEWPARAM(1005, BN_CLICKED), 0);
        CHECK_EQ(main_error_calls, 1);
        CHECK_EQ(main_error_action, L"导出 CSV 失败");
        CHECK_EQ(main_error_code, static_cast<DWORD>(ERROR_ACCESS_DENIED));
        main_csv_result = {false, ERROR_SUCCESS};
        SendMessageW(window, WM_COMMAND, MAKEWPARAM(1005, BN_CLICKED), 0);
        CHECK_EQ(main_error_calls, 1);
        ListView_SetItemState(list, 0, LVIS_FOCUSED | LVIS_SELECTED,
                              LVIS_FOCUSED | LVIS_SELECTED);
        main_menu_command = 1006;
        main_error_calls = 0;
        action_api.open_succeeds = false;
        action_api.last_error = ERROR_ACCESS_DENIED;
        SendMessageW(window, WM_CONTEXTMENU, reinterpret_cast<WPARAM>(list), -1);
        CHECK_EQ(main_menu_labels ==
            (std::vector<std::wstring>{L"查看连接明细", L"打开文件所在位置", L"结束进程"}), true);
        CHECK_EQ(action_api.opened_process_id, 4242UL);
        CHECK_EQ(main_error_calls, 1);
        CHECK_EQ(main_error_action, L"打开文件所在位置");
        CHECK_EQ(main_error_code, static_cast<DWORD>(ERROR_ACCESS_DENIED));
        main_menu_command = 1007;
        main_confirm_calls = 0;
        main_confirm_result = false;
        action_api.open_succeeds = true;
        SendMessageW(window, WM_CONTEXTMENU, reinterpret_cast<WPARAM>(list), -1);
        CHECK_EQ(main_confirm_calls, 1);
        CHECK_EQ(main_confirm_name, L"zeta.exe");
        CHECK_EQ(main_confirm_process.pid, 4242U);
        CHECK_EQ(main_confirm_process.creation_time_100ns, 77ULL);
        CHECK_EQ(action_api.terminate_process_calls, 0);
        main_confirm_result = true;
        SendMessageW(window, WM_CONTEXTMENU, reinterpret_cast<WPARAM>(list), -1);
        CHECK_EQ(action_api.terminate_process_calls, 1);
        action_api.terminate_process_succeeds = false;
        action_api.last_error = ERROR_INVALID_HANDLE;
        SendMessageW(window, WM_CONTEXTMENU, reinterpret_cast<WPARAM>(list), -1);
        CHECK_EQ(action_api.terminate_process_calls, 2);
        CHECK_EQ(main_error_action, L"结束进程");
        CHECK_EQ(main_error_code, static_cast<DWORD>(ERROR_INVALID_HANDLE));
    }
    DestroyWindow(window);
    MSG message{};
    while (PeekMessageW(&message, nullptr, WM_QUIT, WM_QUIT, PM_REMOVE)) {}
}

void TestMainWindowMouseActionKeepsClickedProcessAcrossMenuAndConfirmationRefresh() {
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES};
    CHECK_EQ(InitCommonControlsEx(&controls), TRUE);
    TrafficAggregator traffic;
    ConnectionAggregator connections;
    ProcessInfoCache cache;
    FakeEtwSessionApi etw_api;
    EtwMonitor etw(traffic, connections, cache, etw_api);
    FakeProcessActionApi action_api;
    action_api.creation_time_100ns = 77;
    ProcessActions actions(action_api);
    traffic.Add({{{4242, 77}, TransportProtocol::Tcp, ApplicationProtocol::HttpsTls},
                 L"zeta.exe", TrafficDirection::Send, 1});
    traffic.Add({{{4243, 88}, TransportProtocol::Tcp, ApplicationProtocol::Http},
                 L"mike.exe", TrafficDirection::Send, 1});
    main_reorder_traffic = &traffic;
    main_menu_refreshes = 0;
    main_confirmation_refreshes = 0;
    main_confirm_calls = 0;
    main_confirm_result = true;
    main_menu_command = 1007;
    MainWindowDependencies dependencies{};
    dependencies.process_actions = &actions;
    dependencies.choose_menu_command = ChooseMainMenuAfterRefresh;
    dependencies.confirm_termination = ConfirmMainTerminateAfterRefresh;
    dependencies.present_error = CaptureMainError;
    dependencies.save_csv = CaptureMainCsv;
    HWND window = CreateMainWindow(GetModuleHandleW(nullptr), traffic, connections,
                                   cache, etw, dependencies);
    CHECK_EQ(window != nullptr, true);
    if (window != nullptr) {
        HWND list = FindWindowExW(window, nullptr, WC_LISTVIEWW, nullptr);
        CHECK_EQ(list != nullptr, true);
        if (list != nullptr) {
            NMLISTVIEW sort_click{};
            sort_click.hdr.hwndFrom = list;
            sort_click.hdr.code = LVN_COLUMNCLICK;
            sort_click.iSubItem = 0;
            SendMessageW(window, WM_NOTIFY, 0, reinterpret_cast<LPARAM>(&sort_click));
            wchar_t first_name[64]{};
            wchar_t second_name[64]{};
            ListView_GetItemText(list, 0, 0, first_name, 64);
            ListView_GetItemText(list, 1, 0, second_name, 64);
            CHECK_EQ(std::wstring_view(first_name), L"mike.exe");
            CHECK_EQ(std::wstring_view(second_name), L"zeta.exe");
            ListView_SetItemState(list, 0, LVIS_FOCUSED | LVIS_SELECTED,
                                  LVIS_FOCUSED | LVIS_SELECTED);
            NMITEMACTIVATE right_click{};
            right_click.hdr.hwndFrom = list;
            right_click.hdr.code = NM_RCLICK;
            right_click.iItem = 1;
            SendMessageW(window, WM_NOTIFY, 0, reinterpret_cast<LPARAM>(&right_click));
            CHECK_EQ(main_menu_refreshes, 1);
            CHECK_EQ(main_confirmation_refreshes, 1);
            CHECK_EQ(main_confirm_calls, 1);
            CHECK_EQ(main_confirm_name, L"zeta.exe");
            CHECK_EQ(main_confirm_process.pid, 4242U);
            CHECK_EQ(main_confirm_process.creation_time_100ns, 77ULL);
            CHECK_EQ(action_api.open_process_calls, 1);
            CHECK_EQ(action_api.opened_process_id, 4242UL);
            CHECK_EQ(action_api.get_process_times_calls, 1);
            CHECK_EQ(action_api.terminate_process_calls, 1);
            CHECK_EQ(ListView_GetItemCount(list), 4);
        }
        DestroyWindow(window);
    }
    main_reorder_traffic = nullptr;
    MSG message{};
    while (PeekMessageW(&message, nullptr, WM_QUIT, WM_QUIT, PM_REMOVE)) {}
}

void TestMainWindowShowsProcessRateTotals() {
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES};
    CHECK_EQ(InitCommonControlsEx(&controls), TRUE);
    TrafficAggregator traffic;
    ConnectionAggregator connections;
    ProcessInfoCache cache;
    FakeEtwSessionApi etw_api;
    EtwMonitor etw(traffic, connections, cache, etw_api);
    HWND window = CreateMainWindow(GetModuleHandleW(nullptr), traffic, connections,
                                   cache, etw);
    CHECK_EQ(window != nullptr, true);
    if (window == nullptr) { return; }
    HWND status = FindWindowExW(window, nullptr, STATUSCLASSNAMEW, nullptr);
    CHECK_EQ(status != nullptr, true);
    auto status_text = [&]() {
        std::wstring value(512, L'\0');
        SendMessageW(status, SB_GETTEXTW, 0, reinterpret_cast<LPARAM>(value.data()));
        value.resize(std::wcslen(value.c_str()));
        return value;
    };
    CHECK_EQ(status_text().find(L"进程总网速：↑ 0 B/s ↓ 0 B/s 合计 0 B/s") !=
                 std::wstring::npos, true);
    DestroyWindow(window);
    MSG message{};
    while (PeekMessageW(&message, nullptr, WM_QUIT, WM_QUIT, PM_REMOVE)) {}
}

void TestMainWindowKeepsManualScrollAndResetsForSortAndFilter() {
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES};
    CHECK_EQ(InitCommonControlsEx(&controls), TRUE);
    TrafficAggregator traffic;
    ConnectionAggregator connections;
    ProcessInfoCache cache;
    FakeEtwSessionApi etw_api;
    EtwMonitor etw(traffic, connections, cache, etw_api);
    for (int index = 0; index < 80; ++index) {
        traffic.Add({{{static_cast<std::uint32_t>(5000 + index),
                       static_cast<std::uint64_t>(100 + index)},
                      TransportProtocol::Tcp, ApplicationProtocol::Http},
                     L"proc" + std::to_wstring(100 + index) + L".exe",
                     TrafficDirection::Send, 1});
    }
    HWND window = CreateMainWindow(GetModuleHandleW(nullptr), traffic, connections,
                                   cache, etw);
    CHECK_EQ(window != nullptr, true);
    if (window == nullptr) { return; }
    SetWindowPos(window, nullptr, 0, 0, 900, 240,
                 SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    HWND list = FindWindowExW(window, nullptr, WC_LISTVIEWW, nullptr);
    CHECK_EQ(list != nullptr, true);
    if (list != nullptr) {
        CHECK_EQ(ListView_GetItemCount(list), 80);
        SendMessageW(list, WM_VSCROLL, SB_PAGEDOWN, 0);
        const int old_top = ListView_GetTopIndex(list);
        CHECK_EQ(old_top > 0, true);
        wchar_t anchored_name[64]{};
        ListView_GetItemText(list, old_top, 0, anchored_name,
                             static_cast<int>(std::size(anchored_name)));
        ListView_SetItemState(list, old_top, LVIS_SELECTED, LVIS_SELECTED);
        traffic.Add({{{4000, 999}, TransportProtocol::Tcp, ApplicationProtocol::Http},
                     L"aaa.exe", TrafficDirection::Send, 1});
        SendMessageW(window, WM_TIMER, 1, 0);
        wchar_t restored_name[64]{};
        ListView_GetItemText(list, ListView_GetTopIndex(list), 0, restored_name,
                             static_cast<int>(std::size(restored_name)));
        CHECK_EQ(std::wstring_view(restored_name), std::wstring_view(anchored_name));
        CHECK_EQ((ListView_GetItemState(list, ListView_GetTopIndex(list), LVIS_SELECTED) &
                  LVIS_SELECTED) != 0, true);
        const int removed_top = ListView_GetTopIndex(list);
        traffic.Clear();
        for (int index = 0; index < 80; ++index) {
            const std::wstring name = L"proc" + std::to_wstring(100 + index) + L".exe";
            if (name != anchored_name) {
                traffic.Add({{{static_cast<std::uint32_t>(5000 + index),
                               static_cast<std::uint64_t>(100 + index)},
                              TransportProtocol::Tcp, ApplicationProtocol::Http},
                             name, TrafficDirection::Send, 1});
            }
        }
        traffic.Add({{{4000, 999}, TransportProtocol::Tcp, ApplicationProtocol::Http},
                     L"aaa.exe", TrafficDirection::Send, 1});
        SendMessageW(window, WM_TIMER, 1, 0);
        CHECK_EQ(ListView_GetItemCount(list), 80);
        const int fallback_top = ListView_GetTopIndex(list);
        CHECK_EQ(fallback_top >= 0 && fallback_top < ListView_GetItemCount(list), true);
        CHECK_EQ(fallback_top >= removed_top - 1 && fallback_top <= removed_top + 1, true);
        CHECK_EQ(ListView_GetSelectedCount(list), 0);
        NMLISTVIEW click{};
        click.hdr.hwndFrom = list;
        click.hdr.code = LVN_COLUMNCLICK;
        click.iSubItem = 0;
        SendMessageW(window, WM_NOTIFY, 0, reinterpret_cast<LPARAM>(&click));
        CHECK_EQ(ListView_GetTopIndex(list), 0);
        SendMessageW(list, WM_MOUSEWHEEL,
                     MAKEWPARAM(0, static_cast<WORD>(-WHEEL_DELTA)), 0);
        CHECK_EQ(ListView_GetTopIndex(list) > 0, true);
        HWND filter = GetDlgItem(window, 1003);
        CHECK_EQ(filter != nullptr, true);
        if (filter != nullptr) { SetWindowTextW(filter, L"proc"); }
        CHECK_EQ(ListView_GetTopIndex(list), 0);
        SendMessageW(list, WM_VSCROLL, SB_PAGEDOWN, 0);
        CHECK_EQ(ListView_GetTopIndex(list) > 0, true);
        SendMessageW(list, WM_VSCROLL, SB_TOP, 0);
        CHECK_EQ(ListView_GetTopIndex(list), 0);
        SendMessageW(list, WM_VSCROLL, SB_PAGEDOWN, 0);
        CHECK_EQ(ListView_GetTopIndex(list) > 0, true);
        ListView_SetItemState(list, ListView_GetTopIndex(list), LVIS_FOCUSED, LVIS_FOCUSED);
        SendMessageW(list, WM_KEYDOWN, VK_HOME, 0);
        CHECK_EQ(ListView_GetTopIndex(list), 0);
        traffic.Add({{{3999, 998}, TransportProtocol::Tcp, ApplicationProtocol::Http},
                     L"proc000.exe", TrafficDirection::Send, 1});
        SendMessageW(window, WM_TIMER, 1, 0);
        CHECK_EQ(ListView_GetTopIndex(list), 0);
    }
    DestroyWindow(window);
    MSG message{};
    while (PeekMessageW(&message, nullptr, WM_QUIT, WM_QUIT, PM_REMOVE)) {}
}

thread_local WNDPROC original_detail_list_procedure{};

LRESULT CALLBACK FailDetailColumnProcedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    if (message == LVM_INSERTCOLUMNW) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return -1;
    }
    const LRESULT result = CallWindowProcW(original_detail_list_procedure, window, message, wparam, lparam);
    if (message == WM_NCDESTROY) { SetLastError(ERROR_SUCCESS); }
    return result;
}

LRESULT CALLBACK FailDetailColumnHook(int code, WPARAM wparam, LPARAM lparam) {
    if (code == HCBT_CREATEWND) {
        wchar_t name[64]{};
        HWND window = reinterpret_cast<HWND>(wparam);
        GetClassNameW(window, name, static_cast<int>(std::size(name)));
        if (std::wstring_view(name) == WC_LISTVIEWW) {
            original_detail_list_procedure = reinterpret_cast<WNDPROC>(SetWindowLongPtrW(
                window, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(FailDetailColumnProcedure)));
        }
    }
    return CallNextHookEx(nullptr, code, wparam, lparam);
}

void TestConnectionCreationPreservesErrorAcrossDestruction() {
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES};
    CHECK_EQ(InitCommonControlsEx(&controls), TRUE);
    ConnectionAggregator connections;
    ProcessInfoCache cache;
    const auto key = MakeConnectionKey({42, 100}, TransportProtocol::Tcp,
        ApplicationProtocol::HttpsTls, 50000, 443);
    connections.Add({key, L"test.exe", TrafficDirection::Send, 128, {}});
    HHOOK hook = SetWindowsHookExW(WH_CBT, FailDetailColumnHook, nullptr, GetCurrentThreadId());
    CHECK_EQ(hook != nullptr, true);
    if (hook == nullptr) { return; }
    const auto failed = CreateConnectionWindow(GetModuleHandleW(nullptr), nullptr,
        key.process, L"test.exe", connections, cache);
    UnhookWindowsHookEx(hook);
    CHECK_EQ(failed.window == nullptr, true);
    CHECK_EQ(failed.error, static_cast<DWORD>(ERROR_NOT_ENOUGH_MEMORY));
    if (failed.window != nullptr) { DestroyWindow(failed.window); }
    CHECK_EQ(connections.Snapshot(key.process, {}).size(), 1ULL);
    const auto created = CreateConnectionWindow(GetModuleHandleW(nullptr), nullptr,
        key.process, L"test.exe", connections, cache);
    CHECK_EQ(created.window != nullptr, true);
    CHECK_EQ(created.error, static_cast<DWORD>(ERROR_SUCCESS));
    if (created.window != nullptr) { DestroyWindow(created.window); }
}

thread_local bool destroyed_list_before_subclass = false;

LRESULT CALLBACK DestroyDetailListBeforeSubclassHook(int code, WPARAM wparam, LPARAM lparam) {
    LRESULT next = CallNextHookEx(nullptr, code, wparam, lparam);
    if (code == HC_ACTION && !destroyed_list_before_subclass) {
        const auto* message = reinterpret_cast<const CWPRETSTRUCT*>(lparam);
        wchar_t class_name[32]{};
        GetClassNameW(message->hwnd, class_name, static_cast<int>(std::size(class_name)));
        if (message->message == WM_SETFONT &&
            std::wstring_view(class_name) == WC_LISTVIEWW) {
            destroyed_list_before_subclass = DestroyWindow(message->hwnd) != FALSE;
            if (destroyed_list_before_subclass) {
                SetLastError(ERROR_ACCESS_DENIED);
            }
        }
    }
    return next;
}

void TestConnectionCreationDoesNotUseStaleSubclassFailureError() {
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES};
    CHECK_EQ(InitCommonControlsEx(&controls), TRUE);
    ConnectionAggregator connections;
    ProcessInfoCache cache;
    destroyed_list_before_subclass = false;
    HHOOK hook = SetWindowsHookExW(WH_CALLWNDPROCRET,
        DestroyDetailListBeforeSubclassHook, nullptr, GetCurrentThreadId());
    CHECK_EQ(hook != nullptr, true);
    if (hook == nullptr) { return; }
    const auto failed = CreateConnectionWindow(GetModuleHandleW(nullptr), nullptr,
        {42, 100}, L"test.exe", connections, cache);
    UnhookWindowsHookEx(hook);
    CHECK_EQ(destroyed_list_before_subclass, true);
    CHECK_EQ(failed.window == nullptr, true);
    CHECK_EQ(failed.error != ERROR_SUCCESS, true);
    CHECK_EQ(failed.error != ERROR_ACCESS_DENIED, true);
    if (failed.window != nullptr) { DestroyWindow(failed.window); }
}

void TestConnectionWindowCreatesFilterAndExportToolbar() {
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES};
    CHECK_EQ(InitCommonControlsEx(&controls), TRUE);
    ConnectionAggregator connections;
    ProcessInfoCache cache;
    const auto created = CreateConnectionWindow(GetModuleHandleW(nullptr), nullptr,
        {42, 100}, L"test.exe", connections, cache);
    CHECK_EQ(created.window != nullptr, true);
    if (created.window == nullptr) { return; }

    int edit_count = 0;
    bool has_export_button = false;
    HWND list = nullptr;
    for (HWND child = GetWindow(created.window, GW_CHILD); child != nullptr;
         child = GetWindow(child, GW_HWNDNEXT)) {
        wchar_t class_name[32]{};
        wchar_t title[32]{};
        GetClassNameW(child, class_name, static_cast<int>(std::size(class_name)));
        GetWindowTextW(child, title, static_cast<int>(std::size(title)));
        if (std::wstring_view(class_name) == L"Edit") { ++edit_count; }
        if (std::wstring_view(class_name) == L"Button" &&
            std::wstring_view(title) == L"导出 CSV") { has_export_button = true; }
        if (std::wstring_view(class_name) == WC_LISTVIEWW) { list = child; }
    }
    CHECK_EQ(edit_count, 2);
    CHECK_EQ(has_export_button, true);
    CHECK_EQ(list != nullptr, true);
    SetWindowPos(created.window, nullptr, 0, 0, 900, 240,
                 SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    RECT client{};
    GetClientRect(created.window, &client);
    for (HWND child = GetWindow(created.window, GW_CHILD); child != nullptr;
         child = GetWindow(child, GW_HWNDNEXT)) {
        RECT bounds{};
        GetWindowRect(child, &bounds);
        MapWindowPoints(nullptr, created.window,
                        reinterpret_cast<POINT*>(&bounds), 2);
        CHECK_EQ(bounds.left >= 0 && bounds.top >= 0 &&
                 bounds.right <= client.right && bounds.bottom <= client.bottom, true);
    }
    if (list != nullptr) {
        RECT list_rect{};
        GetWindowRect(list, &list_rect);
        MapWindowPoints(nullptr, created.window,
                        reinterpret_cast<POINT*>(&list_rect), 2);
        CHECK_EQ(list_rect.top > 30, true);
    }
    DestroyWindow(created.window);
}

void TestConnectionWindowSeparatesTcpAndUdpIntoTabs() {
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES};
    CHECK_EQ(InitCommonControlsEx(&controls), TRUE);
    ConnectionAggregator connections;
    ProcessInfoCache cache;
    const ProcessInstanceId process{42, 100};
    const auto now = std::chrono::steady_clock::now();
    connections.Add({MakeConnectionKey(process, TransportProtocol::Tcp,
        ApplicationProtocol::HttpsTls, 50000, 443), L"test.exe",
        TrafficDirection::Send, 128, now});
    connections.Add({MakeConnectionKey(process, TransportProtocol::Udp,
        ApplicationProtocol::Dns, 53000, 53), L"test.exe",
        TrafficDirection::Receive, 64, now});
    const auto created = CreateConnectionWindow(GetModuleHandleW(nullptr), nullptr,
        process, L"test.exe", connections, cache);
    CHECK_EQ(created.window != nullptr, true);
    if (created.window == nullptr) { return; }

    SendMessageW(created.window, kConnectionWindowRefreshMessage, 0, 0);
    HWND tab = FindWindowExW(created.window, nullptr, WC_TABCONTROLW, nullptr);
    std::vector<HWND> lists;
    for (HWND child = FindWindowExW(created.window, nullptr, WC_LISTVIEWW, nullptr);
         child != nullptr;
         child = FindWindowExW(created.window, child, WC_LISTVIEWW, nullptr)) {
        lists.push_back(child);
    }
    CHECK_EQ(tab != nullptr, true);
    CHECK_EQ(lists.size(), 2U);
    if (tab != nullptr && lists.size() == 2) {
        CHECK_EQ(TabCtrl_GetItemCount(tab), 2);
        CHECK_EQ(ListView_GetItemCount(lists[0]), 1);
        CHECK_EQ(ListView_GetItemCount(lists[1]), 1);
        CHECK_EQ((GetWindowLongPtrW(lists[0], GWL_STYLE) & WS_VISIBLE) != 0, true);
        CHECK_EQ((GetWindowLongPtrW(lists[1], GWL_STYLE) & WS_VISIBLE) != 0, false);

        TabCtrl_SetCurSel(tab, 1);
        NMHDR changed{tab, 0, TCN_SELCHANGE};
        SendMessageW(created.window, WM_NOTIFY, 0, reinterpret_cast<LPARAM>(&changed));
        CHECK_EQ((GetWindowLongPtrW(lists[0], GWL_STYLE) & WS_VISIBLE) != 0, false);
        CHECK_EQ((GetWindowLongPtrW(lists[1], GWL_STYLE) & WS_VISIBLE) != 0, true);
    }
    DestroyWindow(created.window);
}

void TestConnectionWindowStartsWideEnoughForDetailColumns() {
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES};
    CHECK_EQ(InitCommonControlsEx(&controls), TRUE);
    ConnectionAggregator connections;
    ProcessInfoCache cache;
    const auto created = CreateConnectionWindow(GetModuleHandleW(nullptr), nullptr,
        {42, 100}, L"test.exe", connections, cache);
    CHECK_EQ(created.window != nullptr, true);
    if (created.window == nullptr) { return; }

    RECT client{};
    CHECK_EQ(GetClientRect(created.window, &client), TRUE);
    CHECK_EQ(client.right - client.left, win32_dpi::Scale(1450, win32_dpi::System()));
    DestroyWindow(created.window);
}

int detail_error_count = 0;
DWORD detail_error_code = ERROR_SUCCESS;
std::wstring detail_error_operation;

void CaptureDetailError(HWND, std::wstring_view operation, DWORD code) {
    ++detail_error_count;
    detail_error_code = code;
    detail_error_operation = operation;
}

void TestConnectionWindowFiltersBothEndpointsAndPreservesValidPort() {
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES};
    CHECK_EQ(InitCommonControlsEx(&controls), TRUE);
    ConnectionAggregator connections;
    ProcessInfoCache cache;
    const ProcessInstanceId process{42, 100};
    const auto now = std::chrono::steady_clock::now();
    connections.Add({MakeConnectionKey(process, TransportProtocol::Tcp,
        ApplicationProtocol::HttpsTls, 50000, 443), L"test.exe",
        TrafficDirection::Send, 128, now});
    connections.Add({MakeConnectionKey(process, TransportProtocol::Tcp,
        ApplicationProtocol::HttpsTls, 50001, 80,
        MakeIpv4Address(10, 0, 0, 2), MakeIpv4Address(1, 1, 1, 1)),
        L"test.exe", TrafficDirection::Send, 64, now});
    const auto created = CreateConnectionWindow(GetModuleHandleW(nullptr), nullptr,
        process, L"test.exe", connections, cache, CaptureDetailError);
    CHECK_EQ(created.window != nullptr, true);
    if (created.window == nullptr) { return; }
    HWND edits[2]{};
    int edit_count = 0;
    HWND list = nullptr;
    for (HWND child = GetWindow(created.window, GW_CHILD); child != nullptr;
         child = GetWindow(child, GW_HWNDNEXT)) {
        wchar_t class_name[32]{};
        GetClassNameW(child, class_name, static_cast<int>(std::size(class_name)));
        if (std::wstring_view(class_name) == L"Edit") {
            ++edit_count;
            if (GetDlgCtrlID(child) == 102) { edits[0] = child; }
            if (GetDlgCtrlID(child) == 101) { edits[1] = child; }
        }
        if (std::wstring_view(class_name) == WC_LISTVIEWW && list == nullptr) {
            list = child;
        }
    }
    CHECK_EQ(edit_count, 2);
    CHECK_EQ(edits[0] != nullptr, true);
    CHECK_EQ(edits[1] != nullptr, true);
    CHECK_EQ(list != nullptr, true);
    if (edits[0] != nullptr && edits[1] != nullptr && list != nullptr) {
        SendMessageW(created.window, kConnectionWindowRefreshMessage, 0, 0);
        CHECK_EQ(ListView_GetItemCount(list), 2);
        SetWindowTextW(edits[0], L"1.1.1.1");
        CHECK_EQ(ListView_GetItemCount(list), 1);
        SetWindowTextW(edits[1], L"80");
        CHECK_EQ(ListView_GetItemCount(list), 1);
        detail_error_count = 0;
        SetWindowTextW(edits[1], L" 80 ");
        CHECK_EQ(ListView_GetItemCount(list), 1);
        CHECK_EQ(detail_error_count, 0);
        SetWindowTextW(edits[0], L"10.0.0.1");
        CHECK_EQ(ListView_GetItemCount(list), 0);
        SetWindowTextW(edits[1], L"50000");
        CHECK_EQ(ListView_GetItemCount(list), 1);
        SetWindowTextW(edits[0], L"10.0.0.2");
        CHECK_EQ(ListView_GetItemCount(list), 0);
        SetWindowTextW(edits[1], L"80");
        CHECK_EQ(ListView_GetItemCount(list), 1);
        detail_error_count = 0;
        SetWindowTextW(edits[1], L"invalid");
        CHECK_EQ(ListView_GetItemCount(list), 1);
        CHECK_EQ(detail_error_count, 1);
        CHECK_EQ(detail_error_code, static_cast<DWORD>(ERROR_INVALID_DATA));
        CHECK_EQ(detail_error_operation.find(L"端口") != std::wstring::npos, true);
        SetWindowTextW(edits[1], L"still invalid");
        CHECK_EQ(detail_error_count, 1);
        SetWindowTextW(edits[1], L"443");
        CHECK_EQ(ListView_GetItemCount(list), 0);
        SetWindowTextW(edits[1], L"");
        CHECK_EQ(ListView_GetItemCount(list), 1);
    }
    DestroyWindow(created.window);
}

void TestConnectionWindowColumnClickMarksHeaderAndResetsTop() {
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES};
    CHECK_EQ(InitCommonControlsEx(&controls), TRUE);
    ConnectionAggregator connections;
    ProcessInfoCache cache;
    const auto created = CreateConnectionWindow(GetModuleHandleW(nullptr), nullptr,
        {42, 100}, L"test.exe", connections, cache);
    CHECK_EQ(created.window != nullptr, true);
    if (created.window == nullptr) { return; }
    HWND list = FindWindowExW(created.window, nullptr, WC_LISTVIEWW, nullptr);
    CHECK_EQ(list != nullptr, true);
    if (list != nullptr) {
        HWND header = ListView_GetHeader(list);
        HDITEMW item{};
        item.mask = HDI_FORMAT;
        CHECK_EQ(Header_GetItem(header, 0, &item) != FALSE, true);
        CHECK_EQ((item.fmt & (HDF_SORTUP | HDF_SORTDOWN)) == 0, true);
        NMLISTVIEW click{};
        click.hdr.hwndFrom = list;
        click.hdr.code = LVN_COLUMNCLICK;
        click.iSubItem = 5;
        SendMessageW(created.window, WM_NOTIFY, 0, reinterpret_cast<LPARAM>(&click));
        CHECK_EQ(Header_GetItem(header, 5, &item) != FALSE, true);
        CHECK_EQ((item.fmt & HDF_SORTUP) != 0, true);
        SendMessageW(created.window, WM_NOTIFY, 0, reinterpret_cast<LPARAM>(&click));
        CHECK_EQ(Header_GetItem(header, 5, &item) != FALSE, true);
        CHECK_EQ((item.fmt & HDF_SORTDOWN) != 0, true);
    }
    DestroyWindow(created.window);
}

void TestConnectionCsvCellsMatchAllTwelveVisibleValues() {
    ConnectionDisplayRow row{};
    row.connection.key = MakeConnectionKey({42, 100}, TransportProtocol::Tcp,
        ApplicationProtocol::HttpsTls, 50000, 443);
    row.connection.sent_bytes = 1024;
    row.connection.sent_bytes_per_second = 2048;
    row.connection.received_bytes = 4096;
    row.connection.received_bytes_per_second = 512;
    row.status = ConnectionActivityStatus::Active;
    row.direction = ConnectionDirection::Bidirectional;
    const auto cells = ConnectionCsvCells(row);
    const std::vector<std::wstring> expected{
        L"活跃", L"双向", L"TCP", L"HTTPS/TLS（端口推断）", L"10.0.0.1",
        L"50000", L"8.8.8.8", L"443", L"1 KB", L"2 KB/s", L"4 KB", L"512 B/s"};
    CHECK_EQ(cells.size(), expected.size());
    for (std::size_t index = 0; index < std::min(cells.size(), expected.size()); ++index) {
        CHECK_EQ(cells[index], expected[index]);
    }
}

void TestConnectionWindowSortClickReturnsScrolledListToTop() {
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES};
    CHECK_EQ(InitCommonControlsEx(&controls), TRUE);
    ConnectionAggregator connections;
    ProcessInfoCache cache;
    const ProcessInstanceId process{42, 100};
    const auto now = std::chrono::steady_clock::now();
    for (std::uint16_t port = 50000; port < 50040; ++port) {
        connections.Add({MakeConnectionKey(process, TransportProtocol::Tcp,
            ApplicationProtocol::HttpsTls, port, 443), L"test.exe",
            TrafficDirection::Send, port, now});
    }
    const auto created = CreateConnectionWindow(GetModuleHandleW(nullptr), nullptr,
        process, L"test.exe", connections, cache);
    CHECK_EQ(created.window != nullptr, true);
    if (created.window == nullptr) { return; }
    SetWindowPos(created.window, nullptr, 0, 0, 900, 240,
                 SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    HWND list = FindWindowExW(created.window, nullptr, WC_LISTVIEWW, nullptr);
    if (list != nullptr) {
        SendMessageW(created.window, kConnectionWindowRefreshMessage, 0, 0);
        SendMessageW(list, WM_VSCROLL, SB_PAGEDOWN, 0);
        CHECK_EQ(ListView_GetTopIndex(list) > 0, true);
        NMLISTVIEW click{};
        click.hdr.hwndFrom = list;
        click.hdr.code = LVN_COLUMNCLICK;
        click.iSubItem = 5;
        SendMessageW(created.window, WM_NOTIFY, 0, reinterpret_cast<LPARAM>(&click));
        CHECK_EQ(ListView_GetTopIndex(list), 0);
        SendMessageW(list, WM_VSCROLL, SB_PAGEDOWN, 0);
        const int anchored_top = ListView_GetTopIndex(list);
        CHECK_EQ(anchored_top > 0, true);
        ListView_SetItemState(list, anchored_top, LVIS_SELECTED, LVIS_SELECTED);
        wchar_t anchored_port[32]{};
        ListView_GetItemText(list, anchored_top, 5, anchored_port,
                             static_cast<int>(std::size(anchored_port)));
        connections.Add({MakeConnectionKey(process, TransportProtocol::Tcp,
            ApplicationProtocol::HttpsTls, 49999, 443), L"test.exe",
            TrafficDirection::Send, 1, now});
        SendMessageW(created.window, kConnectionWindowRefreshMessage, 0, 0);
        wchar_t restored_port[32]{};
        ListView_GetItemText(list, ListView_GetTopIndex(list), 5, restored_port,
                             static_cast<int>(std::size(restored_port)));
        CHECK_EQ(std::wstring_view(restored_port), std::wstring_view(anchored_port));
        CHECK_EQ((ListView_GetItemState(list, anchored_top + 1, LVIS_SELECTED) &
                  LVIS_SELECTED) != 0, true);
        const int removed_top = ListView_GetTopIndex(list);
        connections.Clear();
        connections.Add({MakeConnectionKey(process, TransportProtocol::Tcp,
            ApplicationProtocol::HttpsTls, 49999, 443), L"test.exe",
            TrafficDirection::Send, 1, now});
        for (std::uint16_t port = 50000; port < 50040; ++port) {
            if (std::to_wstring(port) != anchored_port) {
                connections.Add({MakeConnectionKey(process, TransportProtocol::Tcp,
                    ApplicationProtocol::HttpsTls, port, 443), L"test.exe",
                    TrafficDirection::Send, port, now});
            }
        }
        SendMessageW(created.window, kConnectionWindowRefreshMessage, 0, 0);
        CHECK_EQ(ListView_GetItemCount(list), 40);
        const int fallback_top = ListView_GetTopIndex(list);
        CHECK_EQ(fallback_top >= 0 && fallback_top < ListView_GetItemCount(list), true);
        CHECK_EQ(fallback_top >= removed_top - 1 && fallback_top <= removed_top + 1, true);
        CHECK_EQ(ListView_GetSelectedCount(list), 0);
        SendMessageW(list, WM_VSCROLL, SB_PAGEDOWN, 0);
        CHECK_EQ(ListView_GetTopIndex(list) > 0, true);
        HWND ip_edit = GetDlgItem(created.window, 102);
        CHECK_EQ(ip_edit != nullptr, true);
        if (ip_edit != nullptr) { SetWindowTextW(ip_edit, L"10.0.0.1"); }
        CHECK_EQ(ListView_GetTopIndex(list), 0);
        connections.Add({MakeConnectionKey(process, TransportProtocol::Tcp,
            ApplicationProtocol::HttpsTls, 49998, 443), L"test.exe",
            TrafficDirection::Send, 1, now});
        SendMessageW(created.window, kConnectionWindowRefreshMessage, 0, 0);
        CHECK_EQ(ListView_GetTopIndex(list), 0);
        connections.Clear();
        SendMessageW(created.window, kConnectionWindowRefreshMessage, 0, 0);
        CHECK_EQ(ListView_GetItemCount(list), 0);
    }
    DestroyWindow(created.window);
}

void TestConnectionWindowWheelAndNavigationPreserveUserScrollIntent() {
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES};
    CHECK_EQ(InitCommonControlsEx(&controls), TRUE);
    ConnectionAggregator connections;
    ProcessInfoCache cache;
    const ProcessInstanceId process{42, 100};
    const auto now = std::chrono::steady_clock::now();
    for (std::uint16_t port = 50000; port < 50080; ++port) {
        connections.Add({MakeConnectionKey(process, TransportProtocol::Tcp,
            ApplicationProtocol::HttpsTls, port, 443), L"test.exe",
            TrafficDirection::Send, port, now});
    }
    const auto created = CreateConnectionWindow(GetModuleHandleW(nullptr), nullptr,
        process, L"test.exe", connections, cache);
    CHECK_EQ(created.window != nullptr, true);
    if (created.window == nullptr) { return; }
    SetWindowPos(created.window, nullptr, 0, 0, 900, 240,
                 SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    HWND list = FindWindowExW(created.window, nullptr, WC_LISTVIEWW, nullptr);
    CHECK_EQ(list != nullptr, true);
    if (list != nullptr) {
        SendMessageW(created.window, kConnectionWindowRefreshMessage, 0, 0);
        NMLISTVIEW click{};
        click.hdr.hwndFrom = list;
        click.hdr.code = LVN_COLUMNCLICK;
        click.iSubItem = 5;
        SendMessageW(created.window, WM_NOTIFY, 0, reinterpret_cast<LPARAM>(&click));
        connections.Add({MakeConnectionKey(process, TransportProtocol::Tcp,
            ApplicationProtocol::HttpsTls, 49999, 443), L"test.exe",
            TrafficDirection::Send, 1, now});
        SendMessageW(created.window, kConnectionWindowRefreshMessage, 0, 0);
        CHECK_EQ(ListView_GetTopIndex(list), 0);
        connections.Add({MakeConnectionKey(process, TransportProtocol::Tcp,
            ApplicationProtocol::HttpsTls, 49998, 443), L"test.exe",
            TrafficDirection::Send, 1, now});
        SendMessageW(created.window, kConnectionWindowRefreshMessage, 0, 0);
        CHECK_EQ(ListView_GetTopIndex(list), 0);
        SendMessageW(list, WM_MOUSEWHEEL,
            MAKEWPARAM(0, static_cast<WORD>(-WHEEL_DELTA)), 0);
        const int wheel_top = ListView_GetTopIndex(list);
        CHECK_EQ(wheel_top > 0, true);
        wchar_t wheel_port[32]{};
        ListView_GetItemText(list, wheel_top, 5, wheel_port,
                             static_cast<int>(std::size(wheel_port)));
        ListView_SetItemState(list, wheel_top, LVIS_SELECTED, LVIS_SELECTED);
        connections.Add({MakeConnectionKey(process, TransportProtocol::Tcp,
            ApplicationProtocol::HttpsTls, 49997, 443), L"test.exe",
            TrafficDirection::Send, 1, now});
        SendMessageW(created.window, kConnectionWindowRefreshMessage, 0, 0);
        wchar_t restored_port[32]{};
        const int restored_top = ListView_GetTopIndex(list);
        ListView_GetItemText(list, restored_top, 5, restored_port,
                             static_cast<int>(std::size(restored_port)));
        CHECK_EQ(std::wstring_view(restored_port), std::wstring_view(wheel_port));
        CHECK_EQ((ListView_GetItemState(list, restored_top, LVIS_SELECTED) &
                  LVIS_SELECTED) != 0, true);
        connections.Add({MakeConnectionKey(process, TransportProtocol::Tcp,
            ApplicationProtocol::HttpsTls, 49996, 443), L"test.exe",
            TrafficDirection::Send, 1, now});
        SendMessageW(created.window, kConnectionWindowRefreshMessage, 0, 0);
        wchar_t second_restored_port[32]{};
        ListView_GetItemText(list, ListView_GetTopIndex(list), 5, second_restored_port,
                             static_cast<int>(std::size(second_restored_port)));
        CHECK_EQ(std::wstring_view(second_restored_port), std::wstring_view(wheel_port));

        HWND ip_edit = GetDlgItem(created.window, 102);
        CHECK_EQ(ip_edit != nullptr, true);
        RECT item_rect{};
        CHECK_EQ(ListView_GetItemRect(list, 0, &item_rect, LVIR_BOUNDS) != FALSE, true);
        const int row_height = item_rect.bottom - item_rect.top;
        const std::array<WPARAM, 6> navigation{
            VK_END, VK_HOME, VK_NEXT, VK_PRIOR, VK_DOWN, VK_UP};
        for (std::size_t step = 0; step < navigation.size(); ++step) {
            if (ip_edit != nullptr) {
                SetWindowTextW(ip_edit, step % 2 == 0 ? L"10.0.0.1" : L"10.0.0.");
            }
            CHECK_EQ(ListView_GetTopIndex(list), 0);
            ListView_Scroll(list, 0, row_height * 20);
            const int before_key = ListView_GetTopIndex(list);
            CHECK_EQ(before_key > 0, true);
            ListView_SetItemState(list, before_key, LVIS_FOCUSED, LVIS_FOCUSED);
            SendMessageW(list, WM_KEYDOWN, navigation[step], 0);
            const int after_key = ListView_GetTopIndex(list);
            CHECK_EQ(after_key >= 0 && after_key < ListView_GetItemCount(list), true);
            if (navigation[step] == VK_HOME) { CHECK_EQ(after_key, 0); }
            wchar_t key_port[32]{};
            ListView_GetItemText(list, after_key, 5, key_port,
                                 static_cast<int>(std::size(key_port)));
            ListView_SetItemState(list, -1, 0, LVIS_SELECTED);
            ListView_SetItemState(list, after_key, LVIS_SELECTED, LVIS_SELECTED);
            connections.Add({MakeConnectionKey(process, TransportProtocol::Tcp,
                ApplicationProtocol::HttpsTls, static_cast<std::uint16_t>(49995 - step), 443),
                L"test.exe", TrafficDirection::Send, 1, now});
            SendMessageW(created.window, kConnectionWindowRefreshMessage, 0, 0);
            if (after_key == 0) {
                CHECK_EQ(ListView_GetTopIndex(list), 0);
            } else {
                wchar_t stable_port[32]{};
                const int stable_top = ListView_GetTopIndex(list);
                ListView_GetItemText(list, stable_top, 5, stable_port,
                                     static_cast<int>(std::size(stable_port)));
                CHECK_EQ(std::wstring_view(stable_port), std::wstring_view(key_port));
                CHECK_EQ((ListView_GetItemState(list, stable_top, LVIS_SELECTED) &
                          LVIS_SELECTED) != 0, true);
            }
        }
    }
    DestroyWindow(created.window);
}

void TestEtwMonitorQueriesOwnedLossCountersBeforeConcurrentStop() {
    for (int iteration = 0; iteration < 100; ++iteration) {
        TrafficAggregator aggregator;
        ConnectionAggregator connection_aggregator;
        ProcessInfoCache process_cache;
        FakeEtwSessionApi api;
        api.block_query = true;
        api.query_events_lost = std::numeric_limits<ULONG>::max();
        api.query_real_time_buffers_lost = 17;
        EtwMonitor monitor(aggregator, connection_aggregator, process_cache, api);

        CHECK_EQ(monitor.Start(), true);
        CHECK_EQ(api.WaitForConsumers(), true);

        EtwLossCounters observed{};
        std::jthread query_thread([&] { observed = monitor.loss_counters(); });
        CHECK_EQ(api.WaitForQuery(), true);

        std::atomic_bool stop_returned{};
        std::jthread stop_thread([&] {
            monitor.Stop();
            stop_returned.store(true, std::memory_order_release);
        });
        CHECK_EQ(api.WaitForCloseFor(std::chrono::milliseconds(100)), false);
        CHECK_EQ(api.StopCallCount(), 0);
        CHECK_EQ(stop_returned.load(std::memory_order_acquire), false);

        api.ReleaseQuery();
        query_thread.join();
        stop_thread.join();

        CHECK_EQ(stop_returned.load(std::memory_order_acquire), true);
        CHECK_EQ(observed.events_lost, 4294967295ULL);
        CHECK_EQ(observed.real_time_buffers_lost, 17ULL);
        CHECK_EQ(api.control_query_calls, 1);
        CHECK_EQ(api.queried_session_handle, api.session_handle_to_return);
        CHECK_EQ(api.queried_name, api.started_name);
        CHECK_EQ(api.control_stop_calls, 1);
        CHECK_EQ(api.close_trace_calls, 1);
    }
}

void TestEtwMonitorSerializesLossCountersWithConsumerCleanup() {
    TrafficAggregator aggregator;
    ConnectionAggregator connection_aggregator;
    ProcessInfoCache process_cache;
    FakeEtwSessionApi api;
    api.block_process_trace = false;
    api.block_stop = true;
    api.query_events_lost = 5;
    api.query_real_time_buffers_lost = 7;
    api.stop_events_lost = 11;
    api.stop_real_time_buffers_lost = 13;
    api.SetProcessTraceAction([] {});
    api.HoldProcessTraceAction(true);
    EtwMonitor monitor(aggregator, connection_aggregator, process_cache, api);

    CHECK_EQ(monitor.Start(), true);
    CHECK_EQ(api.WaitForConsumers(), true);
    CHECK_EQ(api.WaitForWorkerActionReady(), true);
    const EtwLossCounters queried = monitor.loss_counters();
    CHECK_EQ(queried.events_lost, 5ULL);
    CHECK_EQ(queried.real_time_buffers_lost, 7ULL);

    api.ReleaseWorkerAction();
    CHECK_EQ(api.WaitForStop(), true);

    EtwLossCounters observed{};
    std::mutex loss_mutex;
    std::condition_variable loss_condition;
    bool loss_started{};
    bool loss_returned{};
    std::jthread loss_thread([&] {
        {
            std::lock_guard lock(loss_mutex);
            loss_started = true;
        }
        loss_condition.notify_all();
        observed = monitor.loss_counters();
        {
            std::lock_guard lock(loss_mutex);
            loss_returned = true;
        }
        loss_condition.notify_all();
    });
    {
        std::unique_lock lock(loss_mutex);
        CHECK_EQ(loss_condition.wait_for(lock, std::chrono::seconds(2),
                                         [&] { return loss_started; }),
                 true);
        CHECK_EQ(loss_condition.wait_for(lock, std::chrono::milliseconds(100),
                                         [&] { return loss_returned; }),
                 false);
    }

    api.ReleaseStop();
    loss_thread.join();

    CHECK_EQ(observed.events_lost, 11ULL);
    CHECK_EQ(observed.real_time_buffers_lost, 13ULL);
    CHECK_EQ(api.WaitForClose(), true);
    monitor.Stop();
}

void TestEtwMonitorExposesRealTimeBufferLossSeparately() {
    TrafficAggregator aggregator;
    ConnectionAggregator connection_aggregator;
    ProcessInfoCache process_cache;
    FakeEtwSessionApi api;
    api.query_real_time_buffers_lost = 7;
    EtwMonitor monitor(aggregator, connection_aggregator, process_cache, api);

    CHECK_EQ(monitor.Start(), true);
    CHECK_EQ(api.WaitForConsumers(), true);
    CHECK_EQ(monitor.events_lost(), 0ULL);
    CHECK_EQ(monitor.real_time_buffers_lost(), 7ULL);
    monitor.Stop();
}

void TestEtwMonitorKeepsFinalLossCountersFromSuccessfulStop() {
    TrafficAggregator aggregator;
    ConnectionAggregator connection_aggregator;
    ProcessInfoCache process_cache;
    FakeEtwSessionApi api;
    api.stop_events_lost = 11;
    api.stop_real_time_buffers_lost = 13;
    EtwMonitor monitor(aggregator, connection_aggregator, process_cache, api);

    CHECK_EQ(monitor.Start(), true);
    CHECK_EQ(api.WaitForConsumers(), true);
    monitor.Stop();
    CHECK_EQ(monitor.events_lost(), 11ULL);
    CHECK_EQ(monitor.real_time_buffers_lost(), 13ULL);
}

void TestEtwMonitorRetainsSessionOwnershipAfterFailedStop() {
    TrafficAggregator aggregator;
    ConnectionAggregator connection_aggregator;
    ProcessInfoCache process_cache;
    FakeEtwSessionApi api;
    api.control_stop_statuses = {ERROR_ACCESS_DENIED, ERROR_SUCCESS};
    EtwMonitor monitor(aggregator, connection_aggregator, process_cache, api);

    CHECK_EQ(monitor.Start(), true);
    CHECK_EQ(api.WaitForConsumers(), true);
    monitor.Stop();
    CHECK_EQ(api.control_stop_calls, 1);
    CHECK_EQ(api.close_trace_calls, 1);
    CHECK_EQ(monitor.Start(), false);
    CHECK_EQ(api.start_trace_calls, 1);

    monitor.Stop();
    CHECK_EQ(api.control_stop_calls, 2);
    CHECK_EQ(api.start_trace_calls, 1);
}

void TestEtwMonitorActualCallbackAggregatesCanonicalConnection() {
    constexpr std::uint32_t pid = 1234;
    constexpr std::uint16_t local_port = 50000;
    constexpr std::uint16_t remote_port = 443;
    constexpr std::uint64_t sent_bytes = 2048;
    constexpr std::uint64_t received_bytes = 1024;
    const ProcessInstanceId process_id{pid, 55};
    const auto t0 = std::chrono::steady_clock::time_point{};

    TrafficAggregator traffic_aggregator;
    ConnectionAggregator connection_aggregator;
    FakeProcessInfoApi process_api;
    process_api.query_results = {ProcessInfo{process_id, L"browser.exe", true}};
    process_api.creation_time = process_id.creation_time_100ns;
    ProcessInfoCache process_cache(process_api);
    FakeEtwSessionApi api;
    EtwMonitor monitor(
        traffic_aggregator, connection_aggregator, process_cache, api,
        [](const EVENT_RECORD& record) -> std::optional<EventLayout> {
            const auto opcode = record.EventHeader.EventDescriptor.Opcode;
            if (opcode == EVENT_TRACE_TYPE_SEND) {
                return MakeIpv4Layout(TrafficDirection::Send, TransportProtocol::Tcp);
            }
            if (opcode == EVENT_TRACE_TYPE_RECEIVE) {
                return MakeIpv4Layout(TrafficDirection::Receive, TransportProtocol::Tcp);
            }
            return std::nullopt;
        });
    CHECK_EQ(monitor.Start(), true);
    CHECK_EQ(api.WaitForConsumers(), true);

    std::array send_payload{
        std::byte{0xD2}, std::byte{0x04}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x08}, std::byte{0x00}, std::byte{0x00},
        std::byte{198}, std::byte{51}, std::byte{100}, std::byte{2},
        std::byte{192}, std::byte{0}, std::byte{2}, std::byte{1},
        std::byte{0x01}, std::byte{0xBB}, std::byte{0xC3}, std::byte{0x50},
    };
    EVENT_RECORD send_record{};
    send_record.EventHeader.ProviderId =
        GUID{0x9a280ac0, 0xc8e0, 0x11d1, {0x84, 0xe2, 0x00, 0xc0, 0x4f, 0xb9, 0x98, 0xa2}};
    send_record.EventHeader.EventDescriptor.Opcode = EVENT_TRACE_TYPE_SEND;
    send_record.EventHeader.Flags = EVENT_HEADER_FLAG_64_BIT_HEADER;
    send_record.EventHeader.TimeStamp.QuadPart = 100;
    send_record.UserData = send_payload.data();
    send_record.UserDataLength = static_cast<USHORT>(send_payload.size());
    api.InvokeEventCallback(send_record);

    const auto process_rows = traffic_aggregator.Snapshot(t0);
    const auto detail_rows = connection_aggregator.Snapshot(process_id, t0);
    CHECK_EQ(process_rows.size(), 1ULL);
    CHECK_EQ(detail_rows.size(), 1ULL);
    if (!detail_rows.empty()) {
        CHECK_EQ(detail_rows[0].key.local.port, local_port);
        CHECK_EQ(detail_rows[0].key.remote.port, remote_port);
        CHECK_EQ(detail_rows[0].sent_bytes, sent_bytes);
    }

    std::array receive_payload{
        std::byte{0xD2}, std::byte{0x04}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x04}, std::byte{0x00}, std::byte{0x00},
        std::byte{192}, std::byte{0}, std::byte{2}, std::byte{1},
        std::byte{198}, std::byte{51}, std::byte{100}, std::byte{2},
        std::byte{0xC3}, std::byte{0x50}, std::byte{0x01}, std::byte{0xBB},
    };
    EVENT_RECORD receive_record{};
    receive_record.EventHeader.ProviderId = send_record.EventHeader.ProviderId;
    receive_record.EventHeader.EventDescriptor.Opcode = EVENT_TRACE_TYPE_RECEIVE;
    receive_record.EventHeader.Flags = EVENT_HEADER_FLAG_64_BIT_HEADER;
    receive_record.EventHeader.TimeStamp.QuadPart = 200;
    receive_record.UserData = receive_payload.data();
    receive_record.UserDataLength = static_cast<USHORT>(receive_payload.size());
    api.InvokeEventCallback(receive_record);

    const auto detail_rows_after_receive = connection_aggregator.Snapshot(process_id, t0);
    CHECK_EQ(detail_rows_after_receive.size(), 1ULL);
    if (!detail_rows_after_receive.empty()) {
        CHECK_EQ(detail_rows_after_receive[0].key.local.port, local_port);
        CHECK_EQ(detail_rows_after_receive[0].key.remote.port, remote_port);
        CHECK_EQ(detail_rows_after_receive[0].sent_bytes, sent_bytes);
        CHECK_EQ(detail_rows_after_receive[0].received_bytes, received_bytes);
    }
    CHECK_EQ(process_api.query_process_calls, 1);
    CHECK_EQ(process_api.query_creation_time_calls, 1);
    monitor.Stop();
}

void TestEtwMonitorCallbackContainsExceptionsAndStopsSafely() {
    TrafficAggregator aggregator;
    ConnectionAggregator connection_aggregator;
    ProcessInfoCache process_cache;
    FakeEtwSessionApi api;
    EtwMonitor monitor(
        aggregator, connection_aggregator, process_cache, api,
        [](const EVENT_RECORD&) -> std::optional<EventLayout> {
            throw std::runtime_error("schema failure");
        });
    CHECK_EQ(monitor.Start(), true);
    CHECK_EQ(api.WaitForConsumers(), true);

    std::byte payload{};
    EVENT_RECORD record{};
    record.EventHeader.ProviderId =
        GUID{0x9a280ac0, 0xc8e0, 0x11d1, {0x84, 0xe2, 0x00, 0xc0, 0x4f, 0xb9, 0x98, 0xa2}};
    record.EventHeader.EventDescriptor.Opcode = EVENT_TRACE_TYPE_SEND;
    record.EventHeader.Flags = EVENT_HEADER_FLAG_64_BIT_HEADER;
    record.UserData = &payload;
    record.UserDataLength = 1;
    api.InvokeEventCallback(record);

    CHECK_EQ(api.WaitForClose(), true);
    CHECK_EQ(monitor.running(), false);
    CHECK_EQ(monitor.last_error(), static_cast<ULONG>(ERROR_UNHANDLED_EXCEPTION));
    monitor.Stop();
}

void TestEtwMonitorCallbackContainsLateSubmissionExceptionsAndStopsSafely() {
    const ProcessInstanceId process_id{1234, 55};
    const auto t0 = std::chrono::steady_clock::time_point{};
    TrafficAggregator traffic_aggregator;
    ConnectionAggregator connection_aggregator;
    FakeProcessInfoApi process_api;
    process_api.query_results = {ProcessInfo{process_id, L"browser.exe", true}};
    ProcessInfoCache process_cache(process_api);
    FakeEtwSessionApi api;
    bool traffic_submitted{};
    bool connection_submitted{};
    EtwMonitor monitor(
        traffic_aggregator, connection_aggregator, process_cache, api,
        [](const EVENT_RECORD&) -> std::optional<EventLayout> {
            return MakeIpv4Layout(TrafficDirection::Send, TransportProtocol::Tcp);
        },
        [&](TrafficAggregator& traffic, ConnectionAggregator& connections,
            const TrafficEvent& traffic_event, const ConnectionEvent& connection_event) {
            traffic.Add(traffic_event);
            traffic_submitted = true;
            connections.Add(connection_event);
            connection_submitted = true;
            throw std::runtime_error("submission failure");
        });
    CHECK_EQ(monitor.Start(), true);
    CHECK_EQ(api.WaitForConsumers(), true);

    std::array payload{
        std::byte{0xD2}, std::byte{0x04}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x08}, std::byte{0x00}, std::byte{0x00},
        std::byte{198}, std::byte{51}, std::byte{100}, std::byte{2},
        std::byte{192}, std::byte{0}, std::byte{2}, std::byte{1},
        std::byte{0x01}, std::byte{0xBB}, std::byte{0xC3}, std::byte{0x50},
    };
    EVENT_RECORD record{};
    record.EventHeader.ProviderId =
        GUID{0x9a280ac0, 0xc8e0, 0x11d1, {0x84, 0xe2, 0x00, 0xc0, 0x4f, 0xb9, 0x98, 0xa2}};
    record.EventHeader.EventDescriptor.Opcode = EVENT_TRACE_TYPE_SEND;
    record.EventHeader.Flags = EVENT_HEADER_FLAG_64_BIT_HEADER;
    record.EventHeader.TimeStamp.QuadPart = 100;
    record.UserData = payload.data();
    record.UserDataLength = static_cast<USHORT>(payload.size());
    api.InvokeEventCallback(record);

    CHECK_EQ(traffic_submitted, true);
    CHECK_EQ(connection_submitted, true);
    const auto traffic_rows = traffic_aggregator.Snapshot(t0);
    CHECK_EQ(traffic_rows.size(), 1ULL);
    if (!traffic_rows.empty()) {
        CHECK_EQ(traffic_rows[0].key.process.pid, process_id.pid);
        CHECK_EQ(traffic_rows[0].key.application_protocol, ApplicationProtocol::HttpsTls);
    }
    CHECK_EQ(connection_aggregator.Snapshot(process_id, t0).size(), 1ULL);
    CHECK_EQ(process_api.query_process_calls, 1);
    CHECK_EQ(api.WaitForClose(), true);
    CHECK_EQ(monitor.running(), false);
    CHECK_EQ(monitor.last_error(), static_cast<ULONG>(ERROR_UNHANDLED_EXCEPTION));
    CHECK_EQ(api.control_stop_calls, 1);
    CHECK_EQ(api.close_trace_calls, 1);
    monitor.Stop();
}

void TestClearWaitsForBothEventSubmissions() {
    const ProcessInstanceId process{1234, 55};
    TrafficAggregator traffic;
    ConnectionAggregator connections;
    FakeProcessInfoApi process_api;
    process_api.query_results = {ProcessInfo{process, L"test.exe", true}};
    ProcessInfoCache cache(process_api);
    FakeEtwSessionApi api;
    std::mutex mutex;
    std::condition_variable condition;
    bool first_submitted{}, release_second{}, clear_entered{}, cleared{};
    EtwMonitor monitor(traffic, connections, cache, api,
        [](const EVENT_RECORD&) { return MakeIpv4Layout(TrafficDirection::Send, TransportProtocol::Tcp); },
        [&](TrafficAggregator& main, ConnectionAggregator& detail,
            const TrafficEvent& first, const ConnectionEvent& second) {
            main.Add(first);
            std::unique_lock lock(mutex);
            first_submitted = true;
            condition.notify_all();
            condition.wait(lock, [&] { return release_second; });
            detail.Add(second);
        });
    CHECK_EQ(monitor.Start(), true);
    CHECK_EQ(api.WaitForConsumers(), true);
    std::array<std::byte, 20> payload{};
    payload[0] = std::byte{0xd2}; payload[1] = std::byte{4}; payload[4] = std::byte{64};
    EVENT_RECORD record{};
    record.EventHeader.ProviderId = GUID{0x9a280ac0, 0xc8e0, 0x11d1, {0x84, 0xe2, 0x00, 0xc0, 0x4f, 0xb9, 0x98, 0xa2}};
    record.EventHeader.EventDescriptor.Opcode = EVENT_TRACE_TYPE_SEND;
    record.EventHeader.Flags = EVENT_HEADER_FLAG_64_BIT_HEADER;
    record.UserData = payload.data();
    record.UserDataLength = static_cast<USHORT>(payload.size());
    std::jthread submit([&] { api.InvokeEventCallback(record); });
    {
        std::unique_lock lock(mutex);
        CHECK_EQ(condition.wait_for(lock, std::chrono::seconds(2), [&] { return first_submitted; }), true);
    }
    std::jthread clear([&] {
        { std::lock_guard lock(mutex); clear_entered = true; condition.notify_all(); }
        monitor.ClearStatistics();
        { std::lock_guard lock(mutex); cleared = true; condition.notify_all(); }
    });
    {
        std::unique_lock lock(mutex);
        CHECK_EQ(condition.wait_for(lock, std::chrono::seconds(2), [&] { return clear_entered; }), true);
        CHECK_EQ(condition.wait_for(lock, std::chrono::milliseconds(100), [&] { return cleared; }), false);
        release_second = true;
        condition.notify_all();
    }
    submit.join();
    clear.join();
    CHECK_EQ(traffic.Snapshot(std::chrono::steady_clock::now()).empty(), true);
    CHECK_EQ(connections.Snapshot(process, std::chrono::steady_clock::now()).empty(), true);
    monitor.Stop();
}

void TestEtwMonitorAllowsConsumerThreadStopAndExternalRestart() {
    TrafficAggregator aggregator;
    ConnectionAggregator connection_aggregator;
    ProcessInfoCache process_cache;
    FakeEtwSessionApi api;
    EtwMonitor monitor(aggregator, connection_aggregator, process_cache, api);
    api.SetProcessTraceAction([&] { monitor.Stop(); });

    CHECK_EQ(monitor.Start(), true);
    CHECK_EQ(api.WaitForWorkerAction(), true);
    CHECK_EQ(api.WorkerActionThrew(), false);
    CHECK_EQ(api.control_stop_calls, 1);
    CHECK_EQ(api.close_trace_calls, 1);

    monitor.Stop();
    CHECK_EQ(api.control_stop_calls, 1);
    CHECK_EQ(api.close_trace_calls, 1);

    api.SetProcessTraceAction({});
    CHECK_EQ(monitor.Start(), true);
    CHECK_EQ(api.WaitForConsumers(2), true);
    CHECK_EQ(monitor.running(), true);
    monitor.Stop();
    CHECK_EQ(api.control_stop_calls, 2);
    CHECK_EQ(api.close_trace_calls, 2);
}

void TestEtwMonitorExternalJoinDoesNotBlockConsumerThreadStop() {
    CHECK_EQ(RunEtwMonitorStopInterleavingProcess(), static_cast<DWORD>(ERROR_SUCCESS));
}

void TestCsvBuildEncodesUtf8BomAndEscapesFields() {
    const std::vector<std::wstring> headers{L"进程名", L"说明"};
    const std::vector<std::vector<std::wstring>> rows{
        {L"程序.exe", L"逗号,引号\"和\r\n换行"},
    };

    const CsvBuildResult result = BuildCsvUtf8(headers, rows);

    CHECK_EQ(result.error, static_cast<DWORD>(ERROR_SUCCESS));
    CHECK_EQ(result.bytes,
             "\xEF\xBB\xBF进程名,说明\r\n程序.exe,\"逗号,引号\"\"和\r\n换行\"\r\n");
}

void TestCsvBuildEmptyTableContainsOnlyUtf8Bom() {
    const std::vector<std::wstring> headers;
    const std::vector<std::vector<std::wstring>> rows;

    const CsvBuildResult result = BuildCsvUtf8(headers, rows);

    CHECK_EQ(result.error, static_cast<DWORD>(ERROR_SUCCESS));
    CHECK_EQ(result.bytes, "\xEF\xBB\xBF");
}

void TestCsvBuildRejectsUnevenRows() {
    const std::vector<std::wstring> headers{L"first", L"second"};
    const std::vector<std::vector<std::wstring>> rows{{L"only"}};

    const CsvBuildResult result = BuildCsvUtf8(headers, rows);

    CHECK_EQ(result.error, static_cast<DWORD>(ERROR_INVALID_DATA));
}

void TestWriteCsvFileWritesExactBytesToTemporaryFile() {
    wchar_t temporary_path[MAX_PATH]{};
    const bool has_temporary_path = GetTempPathW(MAX_PATH, temporary_path) > 0;
    CHECK_EQ(has_temporary_path, true);
    if (!has_temporary_path) {
        return;
    }

    wchar_t temporary_file[MAX_PATH]{};
    const bool has_temporary_file = GetTempFileNameW(temporary_path, L"nac", 0, temporary_file) != 0;
    CHECK_EQ(has_temporary_file, true);
    if (!has_temporary_file) {
        return;
    }
    const std::wstring path = temporary_file;
    const std::string bytes{"\xEF\xBB\xBF" "a,b\r\n"};

    CHECK_EQ(WriteCsvFile(path, bytes), static_cast<DWORD>(ERROR_SUCCESS));

    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    CHECK_EQ(file != INVALID_HANDLE_VALUE, true);
    if (file != INVALID_HANDLE_VALUE) {
        std::array<char, 16> actual{};
        DWORD bytes_read{};
        CHECK_EQ(ReadFile(file, actual.data(), static_cast<DWORD>(actual.size()), &bytes_read, nullptr) !=
                     FALSE,
                 true);
        CHECK_EQ(std::string_view(actual.data(), bytes_read), std::string_view(bytes));
        CHECK_EQ(CloseHandle(file) != FALSE, true);
    }
    CHECK_EQ(DeleteFileW(path.c_str()) != FALSE, true);
}

void TestRevealExecutableValidatesInstanceAndSelectsQuotedPath() {
    FakeProcessActionApi api;
    api.creation_time_100ns = 0x1122334455667788ULL;
    api.image_path = L"C:\\Program Files\\odd\"name,tool.exe";
    ProcessActions actions(api);

    const ProcessActionResult result =
        actions.RevealExecutable({4242, api.creation_time_100ns});

    CHECK_EQ(result.succeeded, true);
    CHECK_EQ(result.error, static_cast<DWORD>(ERROR_SUCCESS));
    CHECK_EQ(api.requested_access, static_cast<DWORD>(PROCESS_QUERY_LIMITED_INFORMATION));
    CHECK_EQ(api.opened_inherit_handle, FALSE);
    CHECK_EQ(api.opened_process_id, 4242UL);
    CHECK_EQ(api.timed_handle, api.process_handle);
    CHECK_EQ(api.queried_path_handle, api.process_handle);
    CHECK_EQ(api.queried_path_flags, 0UL);
    CHECK_EQ(api.shell_file, L"explorer.exe");
    CHECK_EQ(api.shell_parameters,
             L"/select,\"C:\\Program Files\\odd\\\"name,tool.exe\"");
    CHECK_EQ(api.shell_mask, static_cast<ULONG>(SEE_MASK_FLAG_NO_UI));
    CHECK_EQ(api.shell_show, SW_SHOWNORMAL);
    CHECK_EQ(api.close_handle_calls, 1);
    CHECK_EQ(api.closed_handle, api.process_handle);
    CHECK_EQ(api.calls.size(), 5U);
    CHECK_EQ(api.calls[0], L"open");
    CHECK_EQ(api.calls[1], L"times");
    CHECK_EQ(api.calls[2], L"path");
    CHECK_EQ(api.calls[3], L"shell");
    CHECK_EQ(api.calls[4], L"close");
}

void TestRevealExecutableRejectsReusedPidBeforePathOrShellAction() {
    FakeProcessActionApi api;
    api.creation_time_100ns = 91;
    ProcessActions actions(api);

    const ProcessActionResult result = actions.RevealExecutable({4242, 92});

    CHECK_EQ(result.succeeded, false);
    CHECK_EQ(result.error, static_cast<DWORD>(ERROR_NOT_FOUND));
    CHECK_EQ(api.query_image_path_calls, 0);
    CHECK_EQ(api.shell_execute_calls, 0);
    CHECK_EQ(api.terminate_process_calls, 0);
    CHECK_EQ(api.close_handle_calls, 1);
    CHECK_EQ(api.calls.size(), 3U);
    CHECK_EQ(api.calls[0], L"open");
    CHECK_EQ(api.calls[1], L"times");
    CHECK_EQ(api.calls[2], L"close");
}

void TestRevealExecutablePropagatesBoundaryFailures() {
    {
        FakeProcessActionApi api;
        api.open_succeeds = false;
        api.last_error = ERROR_FILE_NOT_FOUND;
        ProcessActions actions(api);
        const ProcessActionResult result = actions.RevealExecutable({42, 77});
        CHECK_EQ(result.succeeded, false);
        CHECK_EQ(result.error, static_cast<DWORD>(ERROR_FILE_NOT_FOUND));
        CHECK_EQ(api.close_handle_calls, 0);
    }
    {
        FakeProcessActionApi api;
        api.get_process_times_succeeds = false;
        api.last_error = ERROR_ACCESS_DENIED;
        ProcessActions actions(api);
        const ProcessActionResult result = actions.RevealExecutable({42, 77});
        CHECK_EQ(result.succeeded, false);
        CHECK_EQ(result.error, static_cast<DWORD>(ERROR_ACCESS_DENIED));
        CHECK_EQ(api.query_image_path_calls, 0);
        CHECK_EQ(api.close_handle_calls, 1);
    }
    {
        FakeProcessActionApi api;
        api.query_image_path_succeeds = false;
        api.last_error = ERROR_PATH_NOT_FOUND;
        ProcessActions actions(api);
        const ProcessActionResult result = actions.RevealExecutable({42, 77});
        CHECK_EQ(result.succeeded, false);
        CHECK_EQ(result.error, static_cast<DWORD>(ERROR_PATH_NOT_FOUND));
        CHECK_EQ(api.shell_execute_calls, 0);
        CHECK_EQ(api.close_handle_calls, 1);
    }
    {
        FakeProcessActionApi api;
        api.shell_execute_succeeds = false;
        api.last_error = ERROR_CANCELLED;
        ProcessActions actions(api);
        const ProcessActionResult result = actions.RevealExecutable({42, 77});
        CHECK_EQ(result.succeeded, false);
        CHECK_EQ(result.error, static_cast<DWORD>(ERROR_CANCELLED));
        CHECK_EQ(api.close_handle_calls, 1);
    }
    {
        FakeProcessActionApi api;
        api.shell_execute_succeeds = false;
        api.last_error = ERROR_SUCCESS;
        ProcessActions actions(api);
        const ProcessActionResult result = actions.RevealExecutable({42, 77});
        CHECK_EQ(result.succeeded, false);
        CHECK_EQ(result.error, static_cast<DWORD>(ERROR_GEN_FAILURE));
    }
}

void TestTerminateValidatesInstanceWithOnlyRequiredRights() {
    FakeProcessActionApi api;
    api.creation_time_100ns = 77;
    ProcessActions actions(api);

    const ProcessActionResult result = actions.Terminate({4242, 77});

    CHECK_EQ(result.succeeded, true);
    CHECK_EQ(result.error, static_cast<DWORD>(ERROR_SUCCESS));
    CHECK_EQ(api.requested_access,
             static_cast<DWORD>(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE));
    CHECK_EQ(api.opened_inherit_handle, FALSE);
    CHECK_EQ(api.opened_process_id, 4242UL);
    CHECK_EQ(api.get_process_times_calls, 1);
    CHECK_EQ(api.terminate_process_calls, 1);
    CHECK_EQ(api.terminated_handle, api.process_handle);
    CHECK_EQ(api.terminate_exit_code, 1U);
    CHECK_EQ(api.close_handle_calls, 1);
    CHECK_EQ(api.calls.size(), 4U);
    CHECK_EQ(api.calls[0], L"open");
    CHECK_EQ(api.calls[1], L"times");
    CHECK_EQ(api.calls[2], L"terminate");
    CHECK_EQ(api.calls[3], L"close");
}

void TestTerminateRejectsReusedPidWithoutTerminating() {
    FakeProcessActionApi api;
    api.creation_time_100ns = 91;
    ProcessActions actions(api);

    const ProcessActionResult result = actions.Terminate({4242, 92});

    CHECK_EQ(result.succeeded, false);
    CHECK_EQ(result.error, static_cast<DWORD>(ERROR_NOT_FOUND));
    CHECK_EQ(api.terminate_process_calls, 0);
    CHECK_EQ(api.close_handle_calls, 1);
}

void TestTerminatePropagatesBoundaryFailures() {
    {
        FakeProcessActionApi api;
        api.open_succeeds = false;
        api.last_error = ERROR_ACCESS_DENIED;
        ProcessActions actions(api);
        const ProcessActionResult result = actions.Terminate({42, 77});
        CHECK_EQ(result.succeeded, false);
        CHECK_EQ(result.error, static_cast<DWORD>(ERROR_ACCESS_DENIED));
    }
    {
        FakeProcessActionApi api;
        api.get_process_times_succeeds = false;
        api.last_error = ERROR_INVALID_HANDLE;
        ProcessActions actions(api);
        const ProcessActionResult result = actions.Terminate({42, 77});
        CHECK_EQ(result.succeeded, false);
        CHECK_EQ(result.error, static_cast<DWORD>(ERROR_INVALID_HANDLE));
        CHECK_EQ(api.terminate_process_calls, 0);
        CHECK_EQ(api.close_handle_calls, 1);
    }
    {
        FakeProcessActionApi api;
        api.terminate_process_succeeds = false;
        api.last_error = ERROR_ACCESS_DENIED;
        ProcessActions actions(api);
        const ProcessActionResult result = actions.Terminate({42, 77});
        CHECK_EQ(result.succeeded, false);
        CHECK_EQ(result.error, static_cast<DWORD>(ERROR_ACCESS_DENIED));
        CHECK_EQ(api.close_handle_calls, 1);
    }
    {
        FakeProcessActionApi api;
        api.terminate_process_succeeds = false;
        api.last_error = ERROR_SUCCESS;
        ProcessActions actions(api);
        const ProcessActionResult result = actions.Terminate({42, 77});
        CHECK_EQ(result.succeeded, false);
        CHECK_EQ(result.error, static_cast<DWORD>(ERROR_GEN_FAILURE));
    }
}

void TestListScrollStateTracksOnlyUserIntent() {
    ListScrollState state;
    CHECK_EQ(state.auto_top(), true);

    state.ObserveUserScroll(false);
    CHECK_EQ(state.auto_top(), false);

    state.ObserveUserScroll(true);
    CHECK_EQ(state.auto_top(), true);

    state.ObserveUserScroll(false);
    state.ResetToAutoTop();
    CHECK_EQ(state.auto_top(), true);
}

void TestListScrollStateIgnoresNestedProgrammaticRestoration() {
    ListScrollState state;
    state.ObserveUserScroll(false);

    {
        auto outer = state.GuardProgrammaticScroll();
        state.ObserveUserScroll(true);
        {
            auto inner = state.GuardProgrammaticScroll();
            state.ObserveUserScroll(false);
        }
        state.ObserveUserScroll(true);
    }
    CHECK_EQ(state.auto_top(), false);

    state.ObserveUserScroll(true);
    CHECK_EQ(state.auto_top(), true);

    try {
        auto guard = state.GuardProgrammaticScroll();
        state.ObserveUserScroll(false);
        throw std::runtime_error("restore failed");
    } catch (const std::runtime_error&) {
    }
    CHECK_EQ(state.auto_top(), true);

    state.ObserveUserScroll(false);
    CHECK_EQ(state.auto_top(), false);
}

void TestListViewSortIndicatorUpdatesOnlySortFlags() {
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES};
    CHECK_EQ(InitCommonControlsEx(&controls) != FALSE, true);

    HWND list_view = CreateWindowExW(0, WC_LISTVIEWW, L"", WS_POPUP | LVS_REPORT,
                                     0, 0, 320, 200, nullptr, nullptr,
                                     GetModuleHandleW(nullptr), nullptr);
    CHECK_EQ(list_view != nullptr, true);
    if (list_view == nullptr) {
        return;
    }

    for (int column = 0; column < 3; ++column) {
        LVCOLUMNW item{};
        item.mask = LVCF_TEXT | LVCF_WIDTH;
        item.pszText = const_cast<wchar_t*>(L"Column");
        item.cx = 80;
        CHECK_EQ(ListView_InsertColumn(list_view, column, &item), column);
    }

    HWND header = ListView_GetHeader(list_view);
    HDITEMW item{};
    item.mask = HDI_FORMAT;
    CHECK_EQ(Header_GetItem(header, 1, &item) != FALSE, true);
    item.fmt |= HDF_BITMAP_ON_RIGHT;
    CHECK_EQ(Header_SetItem(header, 1, &item) != FALSE, true);

    UpdateListViewSortIndicator(list_view, 1, true);
    CHECK_EQ(Header_GetItem(header, 1, &item) != FALSE, true);
    CHECK_EQ((item.fmt & HDF_SORTUP) != 0, true);
    CHECK_EQ((item.fmt & HDF_SORTDOWN) == 0, true);
    CHECK_EQ((item.fmt & HDF_BITMAP_ON_RIGHT) != 0, true);

    UpdateListViewSortIndicator(list_view, 1, false);
    CHECK_EQ(Header_GetItem(header, 1, &item) != FALSE, true);
    CHECK_EQ((item.fmt & HDF_SORTUP) == 0, true);
    CHECK_EQ((item.fmt & HDF_SORTDOWN) != 0, true);

    UpdateListViewSortIndicator(list_view, 2, true);
    CHECK_EQ(Header_GetItem(header, 1, &item) != FALSE, true);
    CHECK_EQ((item.fmt & (HDF_SORTUP | HDF_SORTDOWN)) == 0, true);
    CHECK_EQ((item.fmt & HDF_BITMAP_ON_RIGHT) != 0, true);
    CHECK_EQ(Header_GetItem(header, 2, &item) != FALSE, true);
    CHECK_EQ((item.fmt & HDF_SORTUP) != 0, true);
    CHECK_EQ((item.fmt & HDF_SORTDOWN) == 0, true);

    UpdateListViewSortIndicator(nullptr, 0, false);
    UpdateListViewSortIndicator(list_view, -1, false);
    UpdateListViewSortIndicator(list_view, 3, false);
    CHECK_EQ(Header_GetItem(header, 2, &item) != FALSE, true);
    CHECK_EQ((item.fmt & HDF_SORTUP) != 0, true);
    CHECK_EQ((item.fmt & HDF_SORTDOWN) == 0, true);

    CHECK_EQ(DestroyWindow(list_view) != FALSE, true);
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string_view(argv[1]) == "--etw-stop-interleaving-child") {
        return RunEtwMonitorStopInterleavingChild();
    }

    CHECK_EQ(InferApplicationProtocol(TransportProtocol::Tcp,
                                      TrafficDirection::Send, 50000, 443),
             ApplicationProtocol::HttpsTls);
    CHECK_EQ(InferApplicationProtocol(TransportProtocol::Udp,
                                      TrafficDirection::Send, 50000, 443),
             ApplicationProtocol::Quic);
    CHECK_EQ(InferApplicationProtocol(TransportProtocol::Udp,
                                      TrafficDirection::Receive, 53, 50000),
             ApplicationProtocol::Dns);
    CHECK_EQ(InferApplicationProtocol(TransportProtocol::Tcp,
                                      TrafficDirection::Send, 50000, 49152),
             ApplicationProtocol::Other);
    CHECK_EQ(InferApplicationProtocol(TransportProtocol::Tcp,
                                      TrafficDirection::Send, 22, 443),
             ApplicationProtocol::HttpsTls);
    CHECK_EQ(InferApplicationProtocol(TransportProtocol::Tcp,
                                      TrafficDirection::Receive, 22, 443),
             ApplicationProtocol::Ssh);
    CHECK_EQ(InferApplicationProtocol(TransportProtocol::Tcp,
                                      TrafficDirection::Send, 22, 49152),
             ApplicationProtocol::Ssh);
    CHECK_EQ(InferApplicationProtocol(TransportProtocol::Tcp,
                                      TrafficDirection::Receive, 49152, 443),
             ApplicationProtocol::HttpsTls);
    CHECK_EQ(ApplicationProtocolName(ApplicationProtocol::HttpsTls),
             L"HTTPS/TLS（端口推断）");
    CHECK_EQ(ApplicationProtocolName(ApplicationProtocol::Other), L"其他");

    TestTrafficAggregationKeepsDistinctKeysAndDirectionsSeparate();
    TestConnectionAggregationUsesAllEndpointAndProtocolFields();
    TestConnectionAggregationSaturatesDirectionalCounters();
    TestConnectionSnapshotsKeepProcessBaselinesIndependent();
    TestConnectionAggregationBoundsEntriesAndClearsState();
    TestConnectionClearResetsProcessSnapshotTimeBaseline();
    TestConnectionAggregationDefaultCapacityIsOneHundredThousand();
    TestEtwPayloadDecodeIsBoundedAndUsesNetworkOrderPorts();
    TestEtwPayloadDecodeCopiesIpv4EndpointAddresses();
    TestEtwPayloadDecodeCopiesIpv6EndpointAddresses();
    TestParseEventLayoutMapsActualTcpIpv4MofOrder();
    TestParseEventLayoutMapsActualUdpIpv6MofOrder();
    TestParseEventLayoutRejectsTargetAddressWidthMismatch();
    TestParseEventLayoutRejectsDuplicateTargetAddressProperty();
    TestParseEventLayoutRejectsMissingTargetAddressProperty();
    TestParseEventLayoutRejectsVariableTargetAddressProperty();
    TestEtwDecoderCachesLayoutsBySchemaKey();
    TestEtwDecoderCachesFailedParsedAddressSchemasOnlyForTargetEvents();
    TestEtwDecoderCachesInvalidLayoutsAndCountsEveryFailedEvent();
    TestEtwDecoderIgnoresNonNetworkAndNonDataEvents();
    TestSyntheticRecordFlowsThroughDecodeResolveClassifyAndAggregate();
    TestTrafficRatesClearAndSaturation();
    TestTrafficRatesIgnoreNonpositiveSnapshotTimes();
    TestTrafficAggregationKeepsApplicationProtocolsSeparate();
    TestConnectionRowsFormatAddressesAndClassifyActivity();
    TestConnectionRowsSortEveryColumnWithBinaryAndKeyTieBreakers();
    TestConnectionFilteringMatchesEndpointsAndPreservesCallerOrder();
    TestPortFilterParsingUsesStrictDecimalPortRules();
    TestConnectionPortFilterMatchesDisplayedPortText();
    TestTrafficFormatting();
    TestTrafficRowsSortByCombinedSpeedAndColumnsDeterministically();
    TestVisibleRowsFilterWithoutMutatingSnapshotAndAttachLiveness();
    TestProcessRateTotalsSumEveryCapturedProcess();
    TestVisibleRowsDefaultOrderUsesCombinedSpeedDescending();
    TestVisibleRowsUsesInvariantUnicodeCaseInsensitiveFilter();
    TestProcessForVisibleRowReturnsProcessInstanceIdentity();
    TestConnectionWindowRegistryErasesOnlyMatchingHandle();
    TestTakeConnectionWindowsMakesDestroyCallbacksSafe();
    TestProcessInfoResolvesLiveAndInaccessibleProcesses();
    TestProcessInfoFallbackDoesNotMaskRealIdentityOrPidReuse();
    TestProcessInfoCacheUsesCreationTimeOnRealCacheHits();
    TestProcessInfoFallbackDetectsAccessiblePidReuseWithinEightEvents();
    TestProcessInfoCreationQueryFailureEventuallyDetectsPidReuse();
    TestSingleInstanceGuardRejectsSecondOwnerAndReleasesName();
    TestEtwMonitorStartsOneConfiguredConsumer();
    TestEtwMonitorStopsOnlyOwnedResourcesAndStopIsIdempotent();
    TestEtwMonitorExposesStartTraceFailureWithoutOpeningConsumer();
    TestEtwMonitorCleansOnlyLegacyNetAssessSessionsAndRetriesResourceFailure();
    TestEtwMonitorCleansOwnedSessionWhenOpenTraceFails();
    TestEtwMonitorCleansOwnedResourcesWhenConsumerFails();
    TestEtwMonitorDoesNotReportSuccessfulPendingStopCodesAsErrors();
    TestEtwMonitorStopPublishesStateOnlyAfterTransitionLock();
    TestEtwMonitorBadLengthStopReleasesOwnershipButRetainsValidCounters();
    TestMainWindowRetriesFailedStopInsteadOfStartingAnotherSession();
    TestMainWindowExplainsEtwLoggerExhaustion();
    TestMainWindowCreatesOperationalToolbarAndSortArrow();
    TestMainWindowRoutesProcessActionsAndExportsVisibleRows();
    TestMainWindowMouseActionKeepsClickedProcessAcrossMenuAndConfirmationRefresh();
    TestMainWindowShowsProcessRateTotals();
    TestMainWindowKeepsManualScrollAndResetsForSortAndFilter();
    TestConnectionCreationPreservesErrorAcrossDestruction();
    TestConnectionCreationDoesNotUseStaleSubclassFailureError();
    TestConnectionWindowCreatesFilterAndExportToolbar();
    TestConnectionWindowSeparatesTcpAndUdpIntoTabs();
    TestConnectionWindowStartsWideEnoughForDetailColumns();
    TestConnectionWindowFiltersBothEndpointsAndPreservesValidPort();
    TestConnectionWindowColumnClickMarksHeaderAndResetsTop();
    TestConnectionCsvCellsMatchAllTwelveVisibleValues();
    TestConnectionWindowSortClickReturnsScrolledListToTop();
    TestConnectionWindowWheelAndNavigationPreserveUserScrollIntent();
    TestEtwMonitorQueriesOwnedLossCountersBeforeConcurrentStop();
    TestEtwMonitorSerializesLossCountersWithConsumerCleanup();
    TestEtwMonitorExposesRealTimeBufferLossSeparately();
    TestEtwMonitorKeepsFinalLossCountersFromSuccessfulStop();
    TestEtwMonitorRetainsSessionOwnershipAfterFailedStop();
    TestEtwMonitorActualCallbackAggregatesCanonicalConnection();
    TestEtwMonitorCallbackContainsExceptionsAndStopsSafely();
    TestEtwMonitorCallbackContainsLateSubmissionExceptionsAndStopsSafely();
    TestClearWaitsForBothEventSubmissions();
    TestEtwMonitorAllowsConsumerThreadStopAndExternalRestart();
    TestEtwMonitorExternalJoinDoesNotBlockConsumerThreadStop();
    TestCsvBuildEncodesUtf8BomAndEscapesFields();
    TestCsvBuildEmptyTableContainsOnlyUtf8Bom();
    TestCsvBuildRejectsUnevenRows();
    TestWriteCsvFileWritesExactBytesToTemporaryFile();
    TestRevealExecutableValidatesInstanceAndSelectsQuotedPath();
    TestRevealExecutableRejectsReusedPidBeforePathOrShellAction();
    TestRevealExecutablePropagatesBoundaryFailures();
    TestTerminateValidatesInstanceWithOnlyRequiredRights();
    TestTerminateRejectsReusedPidWithoutTerminating();
    TestTerminatePropagatesBoundaryFailures();
    TestListScrollStateTracksOnlyUserIntent();
    TestListScrollStateIgnoresNestedProgrammaticRestoration();
    TestListViewSortIndicatorUpdatesOnlySortFlags();

    return failures == 0 ? 0 : 1;
}
