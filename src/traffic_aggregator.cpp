#include "traffic_aggregator.h"

#include <algorithm>
#include <cstdint>
#include <utility>

namespace {

std::uint64_t SaturatingAdd(std::uint64_t current, std::uint64_t increment) {
    return UINT64_MAX - current < increment ? UINT64_MAX : current + increment;
}

}  // namespace

void TrafficAggregator::Add(const TrafficEvent& event) {
    std::lock_guard lock(mutex_);
    auto& entry = entries_[event.key];
    entry.process_name = event.process_name;
    entry.last_activity = std::max(entry.last_activity, event.observed_at);
    if (event.direction == TrafficDirection::Send) {
        entry.sent_bytes = SaturatingAdd(entry.sent_bytes, event.bytes);
    } else {
        entry.received_bytes = SaturatingAdd(entry.received_bytes, event.bytes);
    }
}

std::vector<TrafficSnapshot> TrafficAggregator::Snapshot(
    std::chrono::steady_clock::time_point now) {
    std::lock_guard lock(mutex_);
    const bool has_previous_snapshot = previous_snapshot_time_.has_value();
    const bool has_valid_interval = has_previous_snapshot && now > *previous_snapshot_time_;
    const double elapsed_seconds = has_valid_interval
                                       ? std::chrono::duration<double>(now - *previous_snapshot_time_).count()
                                       : 0.0;
    std::vector<TrafficSnapshot> snapshots;
    snapshots.reserve(entries_.size());
    for (auto& [key, entry] : entries_) {
        TrafficSnapshot snapshot{key, entry.process_name, entry.sent_bytes, entry.received_bytes};
        if (elapsed_seconds > 0.0 && entry.has_previous_snapshot &&
            entry.sent_bytes >= entry.previous_sent_bytes &&
            entry.received_bytes >= entry.previous_received_bytes) {
            snapshot.sent_bytes_per_second =
                static_cast<double>(entry.sent_bytes - entry.previous_sent_bytes) / elapsed_seconds;
            snapshot.received_bytes_per_second =
                static_cast<double>(entry.received_bytes - entry.previous_received_bytes) /
                                                    elapsed_seconds;
        }
        if (!has_previous_snapshot || has_valid_interval) {
            entry.previous_sent_bytes = entry.sent_bytes;
            entry.previous_received_bytes = entry.received_bytes;
            entry.has_previous_snapshot = true;
        }
        snapshots.push_back(std::move(snapshot));
    }
    if (!has_previous_snapshot || has_valid_interval) {
        previous_snapshot_time_ = now;
    }
    return snapshots;
}

std::vector<ProcessInstanceId> TrafficAggregator::ProcessesInactiveBefore(
    std::chrono::steady_clock::time_point cutoff) const {
    std::lock_guard lock(mutex_);
    std::map<ProcessInstanceId, std::chrono::steady_clock::time_point> newest_activity;
    for (const auto& [key, entry] : entries_) {
        auto [position, inserted] =
            newest_activity.try_emplace(key.process, entry.last_activity);
        if (!inserted) {
            position->second = std::max(position->second, entry.last_activity);
        }
    }

    std::vector<ProcessInstanceId> inactive;
    for (const auto& [process, last_activity] : newest_activity) {
        if (last_activity < cutoff) {
            inactive.push_back(process);
        }
    }
    return inactive;
}

void TrafficAggregator::RemoveProcesses(
    std::span<const ProcessInstanceId> processes) {
    std::lock_guard lock(mutex_);
    std::erase_if(entries_, [processes](const auto& item) {
        return std::find(processes.begin(), processes.end(), item.first.process) !=
               processes.end();
    });
}

void TrafficAggregator::Clear() {
    std::lock_guard lock(mutex_);
    entries_.clear();
    previous_snapshot_time_.reset();
}
