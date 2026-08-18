#include "etw_decoder.h"
#include "formatting.h"
#include "process_info.h"
#include "protocol_classifier.h"
#include "traffic_aggregator.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string_view>
#include <vector>

#define NOMINMAX
#include <windows.h>

namespace {

int failures = 0;

template <typename T>
void PrintValue(std::ostream& stream, const T& value) {
    stream << value;
}

void PrintValue(std::ostream& stream, ApplicationProtocol value) {
    stream << static_cast<int>(value);
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

void TestEtwPayloadDecodeIsBoundedAndUsesNetworkOrderPorts() {
    const EventLayout layout{{0, 4}, {4, 4}, {8, 2}, {10, 2},
                             TrafficDirection::Send, TransportProtocol::Tcp};
    const std::array payload{
        std::byte{0x78}, std::byte{0x56}, std::byte{0x34}, std::byte{0x12},
        std::byte{0x04}, std::byte{0x03}, std::byte{0x02}, std::byte{0x01},
        std::byte{0x12}, std::byte{0x34}, std::byte{0xAB}, std::byte{0xCD},
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

void TestEtwDecoderCachesLayoutsBySchemaKey() {
    const EventLayout layout{{0, 4}, {4, 4}, {8, 2}, {10, 2},
                             TrafficDirection::Receive, TransportProtocol::Udp};
    const std::array payload{
        std::byte{0x2A}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x40}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x35}, std::byte{0xC0}, std::byte{0x00},
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

    CHECK_EQ(decoder.Decode(record).has_value(), true);
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
}

}  // namespace

int main() {
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
    TestEtwPayloadDecodeIsBoundedAndUsesNetworkOrderPorts();
    TestEtwDecoderCachesLayoutsBySchemaKey();
    TestEtwDecoderCachesInvalidLayoutsAndCountsEveryFailedEvent();
    TestTrafficRatesClearAndSaturation();
    TestTrafficRatesIgnoreNonpositiveSnapshotTimes();
    TestTrafficAggregationKeepsApplicationProtocolsSeparate();
    TestTrafficFormatting();
    TestTrafficRowsSortByCombinedSpeedAndColumnsDeterministically();
    TestProcessInfoResolvesLiveAndInaccessibleProcesses();

    return failures == 0 ? 0 : 1;
}
