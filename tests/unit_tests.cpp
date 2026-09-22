#include "etw_decoder.h"
#include "etw_monitor.h"
#include "connection_aggregator.h"
#include "connection_view.h"
#include "connection_window.h"
#include "formatting.h"
#include "main_window.h"
#include "process_info.h"
#include "protocol_classifier.h"
#include "traffic_aggregator.h"

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
        if (start_status == ERROR_SUCCESS) {
            *session_handle = session_handle_to_return;
        }
        return start_status;
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
    CHECK_EQ(api.started_name.starts_with(L"NetAssess-"), true);
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
    TestTrafficFormatting();
    TestTrafficRowsSortByCombinedSpeedAndColumnsDeterministically();
    TestVisibleRowsFilterWithoutMutatingSnapshotAndAttachLiveness();
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
    TestEtwMonitorStartsOneConfiguredConsumer();
    TestEtwMonitorStopsOnlyOwnedResourcesAndStopIsIdempotent();
    TestEtwMonitorExposesStartTraceFailureWithoutOpeningConsumer();
    TestEtwMonitorCleansOwnedSessionWhenOpenTraceFails();
    TestEtwMonitorCleansOwnedResourcesWhenConsumerFails();
    TestEtwMonitorDoesNotReportSuccessfulPendingStopCodesAsErrors();
    TestEtwMonitorStopPublishesStateOnlyAfterTransitionLock();
    TestEtwMonitorBadLengthStopReleasesOwnershipButRetainsValidCounters();
    TestMainWindowRetriesFailedStopInsteadOfStartingAnotherSession();
    TestConnectionCreationPreservesErrorAcrossDestruction();
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

    return failures == 0 ? 0 : 1;
}
