#pragma once

#include "traffic_types.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <span>
#include <vector>

ConnectionKey BuildConnectionKey(ProcessInstanceId process, TransportProtocol transport,
                                 ApplicationProtocol application_protocol,
                                 TrafficDirection direction, IpAddress source,
                                 std::uint16_t source_port, IpAddress destination,
                                 std::uint16_t destination_port);

class ConnectionAggregator {
public:
    explicit ConnectionAggregator(std::size_t max_entries = 100000);

    void Add(const ConnectionEvent& event);
    std::vector<ConnectionSnapshot> Snapshot(ProcessInstanceId process,
                                             std::chrono::steady_clock::time_point now);
    std::vector<ProcessInstanceId> ProcessesInactiveBefore(
        std::chrono::steady_clock::time_point cutoff) const;
    void RemoveProcesses(std::span<const ProcessInstanceId> processes);
    void ResetSnapshotBaseline(ProcessInstanceId process);
    void Clear();
    std::uint64_t dropped_detail_events() const;

private:
    struct Entry {
        std::wstring process_name;
        std::uint64_t sent_bytes{};
        std::uint64_t received_bytes{};
        std::uint64_t previous_sent_bytes{};
        std::uint64_t previous_received_bytes{};
        bool has_previous_snapshot{};
        std::chrono::steady_clock::time_point last_activity;
    };

    bool EvictHistoricalEntriesLocked(
        std::chrono::steady_clock::time_point observed_at);

    const std::size_t max_entries_;
    mutable std::mutex mutex_;
    std::map<ConnectionKey, Entry> entries_;
    std::map<ProcessInstanceId, std::chrono::steady_clock::time_point> previous_snapshot_times_;
    std::uint64_t dropped_detail_events_{};
};
