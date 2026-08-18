#include "traffic_aggregator.h"

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
    if (event.direction == TrafficDirection::Send) {
        entry.sent_bytes = SaturatingAdd(entry.sent_bytes, event.bytes);
    } else {
        entry.received_bytes = SaturatingAdd(entry.received_bytes, event.bytes);
    }
}

std::vector<TrafficSnapshot> TrafficAggregator::Snapshot(
    std::chrono::steady_clock::time_point now) {
    std::lock_guard lock(mutex_);
    const double elapsed_seconds = previous_snapshot_time_ && now > *previous_snapshot_time_
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
        entry.previous_sent_bytes = entry.sent_bytes;
        entry.previous_received_bytes = entry.received_bytes;
        entry.has_previous_snapshot = true;
        snapshots.push_back(std::move(snapshot));
    }
    previous_snapshot_time_ = now;
    return snapshots;
}

void TrafficAggregator::Clear() {
    std::lock_guard lock(mutex_);
    entries_.clear();
    previous_snapshot_time_.reset();
}
