#include "connection_aggregator.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <set>
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
    if (existing == entries_.end() && entries_.size() >= max_entries_) {
        if (max_entries_ == 0 || !EvictHistoricalEntriesLocked(event.observed_at)) {
            dropped_detail_events_ = SaturatingAdd(dropped_detail_events_, 1);
            return;
        }
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

bool ConnectionAggregator::EvictHistoricalEntriesLocked(
    std::chrono::steady_clock::time_point observed_at) {
    const auto cutoff = observed_at - std::chrono::seconds(5);
    std::vector<std::pair<std::chrono::steady_clock::time_point, ConnectionKey>>
        candidates;
    for (const auto& [key, entry] : entries_) {
        if (entry.last_activity < cutoff) {
            candidates.emplace_back(entry.last_activity, key);
        }
    }
    if (candidates.empty()) {
        return false;
    }

    std::sort(candidates.begin(), candidates.end(),
              [](const auto& left, const auto& right) {
                  if (left.first != right.first) {
                      return left.first < right.first;
                  }
                  return left.second < right.second;
              });
    const std::size_t batch_size = std::max<std::size_t>(1, max_entries_ / 20);
    const std::size_t erase_count = std::min(batch_size, candidates.size());
    std::set<ProcessInstanceId> affected_processes;
    for (std::size_t index = 0; index < erase_count; ++index) {
        affected_processes.insert(candidates[index].second.process);
        entries_.erase(candidates[index].second);
    }

    for (const ProcessInstanceId process : affected_processes) {
        const auto first = entries_.lower_bound(ConnectionKey{process});
        if (first == entries_.end() || first->first.process != process) {
            previous_snapshot_times_.erase(process);
        }
    }
    return true;
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
    for (auto iterator = entries_.lower_bound(ConnectionKey{process});
         iterator != entries_.end() && iterator->first.process == process; ++iterator) {
        auto& [key, entry] = *iterator;

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

std::vector<ProcessInstanceId> ConnectionAggregator::ProcessesInactiveBefore(
    std::chrono::steady_clock::time_point cutoff) const {
    const auto newest_activity = LatestActivityByProcess();
    std::vector<ProcessInstanceId> inactive;
    for (const auto& [process, last_activity] : newest_activity) {
        if (last_activity < cutoff) {
            inactive.push_back(process);
        }
    }
    return inactive;
}

std::map<ProcessInstanceId, std::chrono::steady_clock::time_point>
ConnectionAggregator::LatestActivityByProcess() const {
    std::lock_guard lock(mutex_);
    std::map<ProcessInstanceId, std::chrono::steady_clock::time_point> newest_activity;
    for (const auto& [key, entry] : entries_) {
        auto [position, inserted] =
            newest_activity.try_emplace(key.process, entry.last_activity);
        if (!inserted) {
            position->second = std::max(position->second, entry.last_activity);
        }
    }

    return newest_activity;
}

void ConnectionAggregator::RemoveProcesses(
    std::span<const ProcessInstanceId> processes) {
    std::lock_guard lock(mutex_);
    const std::set<ProcessInstanceId> selected(processes.begin(), processes.end());
    std::erase_if(entries_, [&selected](const auto& item) {
        return selected.contains(item.first.process);
    });
    for (const ProcessInstanceId process : processes) {
        previous_snapshot_times_.erase(process);
    }
}

void ConnectionAggregator::RemoveProcessesInactiveBefore(
    std::span<const ProcessInstanceId> processes,
    std::chrono::steady_clock::time_point cutoff) {
    std::lock_guard lock(mutex_);
    std::set<ProcessInstanceId> removable(processes.begin(), processes.end());
    for (const auto& [key, entry] : entries_) {
        if (entry.last_activity >= cutoff) {
            removable.erase(key.process);
        }
    }
    std::erase_if(entries_, [&removable](const auto& item) {
        return removable.contains(item.first.process);
    });
    for (const ProcessInstanceId process : removable) {
        previous_snapshot_times_.erase(process);
    }
}

void ConnectionAggregator::ResetSnapshotBaseline(ProcessInstanceId process) {
    std::lock_guard lock(mutex_);
    previous_snapshot_times_.erase(process);
    for (auto iterator = entries_.lower_bound(ConnectionKey{process});
         iterator != entries_.end() && iterator->first.process == process; ++iterator) {
        iterator->second.has_previous_snapshot = false;
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
