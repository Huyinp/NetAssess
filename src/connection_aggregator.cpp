#include "connection_aggregator.h"

#include <cstdint>
#include <limits>
#include <utility>

namespace {

std::uint64_t SaturatingAdd(std::uint64_t current, std::uint64_t increment) {
    return std::numeric_limits<std::uint64_t>::max() - current < increment
               ? std::numeric_limits<std::uint64_t>::max()
               : current + increment;
}

}  // namespace

ConnectionKey BuildConnectionKey(ProcessInstanceId process, TransportProtocol transport,
                                 ApplicationProtocol application_protocol,
                                 TrafficDirection direction, IpAddress source,
                                 std::uint16_t source_port, IpAddress destination,
                                 std::uint16_t destination_port) {
    if (direction == TrafficDirection::Send) {
        return {process, transport, application_protocol, {source, source_port},
                {destination, destination_port}};
    }
    return {process, transport, application_protocol, {destination, destination_port},
            {source, source_port}};
}

ConnectionAggregator::ConnectionAggregator(std::size_t max_entries) : max_entries_(max_entries) {}

void ConnectionAggregator::Add(const ConnectionEvent& event) {
    std::lock_guard lock(mutex_);
    const auto existing = entries_.find(event.key);
    if (existing == entries_.end() && entries_.size() == max_entries_) {
        dropped_detail_events_ = SaturatingAdd(dropped_detail_events_, 1);
        return;
    }

    auto [iterator, inserted] = entries_.try_emplace(event.key);
    Entry& entry = iterator->second;
    entry.process_name = event.process_name;
    if (event.direction == TrafficDirection::Send) {
        entry.sent_bytes = SaturatingAdd(entry.sent_bytes, event.bytes);
    } else {
        entry.received_bytes = SaturatingAdd(entry.received_bytes, event.bytes);
    }
    if (inserted || event.observed_at > entry.last_activity) {
        entry.last_activity = event.observed_at;
    }
}

std::vector<ConnectionSnapshot> ConnectionAggregator::Snapshot(
    ProcessInstanceId process, std::chrono::steady_clock::time_point now) {
    std::lock_guard lock(mutex_);
    const auto previous_time = previous_snapshot_times_.find(process);
    const bool has_previous_snapshot = previous_time != previous_snapshot_times_.end();
    const bool has_valid_interval = has_previous_snapshot && now > previous_time->second;
    const double elapsed_seconds = has_valid_interval
                                       ? std::chrono::duration<double>(now - previous_time->second).count()
                                       : 0.0;
    const bool update_baseline = !has_previous_snapshot || has_valid_interval;

    std::vector<ConnectionSnapshot> snapshots;
    for (auto& [key, entry] : entries_) {
        if (key.process != process) {
            continue;
        }

        ConnectionSnapshot snapshot{key, entry.process_name, entry.sent_bytes, entry.received_bytes,
                                    0.0, 0.0, entry.last_activity};
        if (elapsed_seconds > 0.0 && entry.has_previous_snapshot &&
            entry.sent_bytes >= entry.previous_sent_bytes &&
            entry.received_bytes >= entry.previous_received_bytes) {
            snapshot.sent_bytes_per_second =
                static_cast<double>(entry.sent_bytes - entry.previous_sent_bytes) / elapsed_seconds;
            snapshot.received_bytes_per_second =
                static_cast<double>(entry.received_bytes - entry.previous_received_bytes) / elapsed_seconds;
        }
        if (update_baseline) {
            entry.previous_sent_bytes = entry.sent_bytes;
            entry.previous_received_bytes = entry.received_bytes;
            entry.has_previous_snapshot = true;
        }
        snapshots.push_back(std::move(snapshot));
    }
    if (update_baseline) {
        previous_snapshot_times_[process] = now;
    }
    return snapshots;
}

void ConnectionAggregator::ResetSnapshotBaseline(ProcessInstanceId process) {
    std::lock_guard lock(mutex_);
    previous_snapshot_times_.erase(process);
    for (auto& [key, entry] : entries_) {
        if (key.process == process) {
            entry.has_previous_snapshot = false;
        }
    }
}

void ConnectionAggregator::Clear() {
    std::lock_guard lock(mutex_);
    entries_.clear();
    previous_snapshot_times_.clear();
    dropped_detail_events_ = 0;
}

std::uint64_t ConnectionAggregator::dropped_detail_events() const {
    std::lock_guard lock(mutex_);
    return dropped_detail_events_;
}
