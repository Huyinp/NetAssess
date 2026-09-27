#pragma once

#include "traffic_types.h"

#include <chrono>
#include <map>
#include <mutex>
#include <optional>
#include <vector>

class TrafficAggregator {
public:
    void Add(const TrafficEvent& event);
    std::vector<TrafficSnapshot> Snapshot(std::chrono::steady_clock::time_point now);
    std::vector<ProcessInstanceId> ProcessesInactiveBefore(
        std::chrono::steady_clock::time_point cutoff) const;
    void Clear();

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

    mutable std::mutex mutex_;
    std::map<TrafficKey, Entry> entries_;
    std::optional<std::chrono::steady_clock::time_point> previous_snapshot_time_;
};
