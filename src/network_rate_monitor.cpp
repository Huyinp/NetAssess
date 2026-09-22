#include "network_rate_monitor.h"

#include <cmath>
#include <memory>
#include <unordered_set>
#include <utility>

namespace {

class WindowsNetworkInterfaceApi final : public INetworkInterfaceApi {
public:
    DWORD Query(std::vector<NetworkInterfaceCounters>& rows) override {
        rows.clear();
        PMIB_IF_TABLE2 table{};
        const DWORD error = GetIfTable2(&table);
        if (error != ERROR_SUCCESS) {
            return error;
        }

        std::unique_ptr<MIB_IF_TABLE2, decltype(&FreeMibTable)> table_guard(table, &FreeMibTable);
        if (table == nullptr) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }

        try {
            rows.reserve(table->NumEntries);
            for (ULONG index = 0; index < table->NumEntries; ++index) {
                const MIB_IF_ROW2& row = table->Table[index];
                rows.push_back({row.InterfaceLuid.Value, row.OperStatus,
                                static_cast<NET_IFTYPE>(row.Type), row.InOctets, row.OutOctets});
            }
        } catch (const std::bad_alloc&) {
            rows.clear();
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        return ERROR_SUCCESS;
    }
};

bool IsMonitored(const NetworkInterfaceCounters& row) {
    return row.status == IfOperStatusUp && row.type != IF_TYPE_SOFTWARE_LOOPBACK;
}

bool IsUsableRate(double value) {
    return std::isfinite(value) && value >= 0.0;
}

void AddRate(double rate, double& total) {
    if (!IsUsableRate(rate)) {
        return;
    }
    const double updated_total = total + rate;
    if (IsUsableRate(updated_total)) {
        total = updated_total;
    }
}

}  // namespace

NetworkRateMonitor::NetworkRateMonitor()
    : owned_api_(std::make_unique<WindowsNetworkInterfaceApi>()), api_(*owned_api_) {}

NetworkRateMonitor::NetworkRateMonitor(INetworkInterfaceApi& api) : api_(api) {}

NetworkRateSnapshot NetworkRateMonitor::Snapshot(std::chrono::steady_clock::time_point now) {
    std::vector<NetworkInterfaceCounters> rows;
    const DWORD error = api_.Query(rows);
    if (error != ERROR_SUCCESS) {
        return {0.0, 0.0, error};
    }

    std::unordered_set<std::uint64_t> visible_interfaces;
    visible_interfaces.reserve(rows.size());
    for (const NetworkInterfaceCounters& row : rows) {
        if (IsMonitored(row)) {
            visible_interfaces.insert(row.interface_luid);
        }
    }
    for (auto baseline = baselines_.begin(); baseline != baselines_.end();) {
        if (!visible_interfaces.contains(baseline->first)) {
            baseline = baselines_.erase(baseline);
        } else {
            ++baseline;
        }
    }

    double received_bytes_per_second{};
    double sent_bytes_per_second{};
    for (const NetworkInterfaceCounters& row : rows) {
        if (!IsMonitored(row) || !visible_interfaces.erase(row.interface_luid)) {
            continue;
        }

        const auto baseline = baselines_.find(row.interface_luid);
        if (baseline == baselines_.end()) {
            baselines_.emplace(row.interface_luid, Baseline{row.in_octets, row.out_octets, now});
            continue;
        }

        const double elapsed_seconds =
            std::chrono::duration<double>(now - baseline->second.time).count();
        if (elapsed_seconds <= 0.0 || !std::isfinite(elapsed_seconds) ||
            row.in_octets < baseline->second.in_octets ||
            row.out_octets < baseline->second.out_octets) {
            continue;
        }

        const double received_rate =
            static_cast<double>(row.in_octets - baseline->second.in_octets) / elapsed_seconds;
        const double sent_rate =
            static_cast<double>(row.out_octets - baseline->second.out_octets) / elapsed_seconds;
        if (!IsUsableRate(received_rate) || !IsUsableRate(sent_rate)) {
            continue;
        }

        AddRate(received_rate, received_bytes_per_second);
        AddRate(sent_rate, sent_bytes_per_second);
        baseline->second = {row.in_octets, row.out_octets, now};
    }
    return {received_bytes_per_second, sent_bytes_per_second, ERROR_SUCCESS};
}
