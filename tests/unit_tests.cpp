#include "protocol_classifier.h"
#include "traffic_aggregator.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string_view>
#include <vector>

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
    TestTrafficRatesClearAndSaturation();

    return failures == 0 ? 0 : 1;
}
