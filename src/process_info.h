#pragma once

#include "traffic_types.h"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

struct ProcessInfo {
    ProcessInstanceId id;
    std::wstring name;
    bool alive{};
};

enum class ProcessProbeResult {
    Running,
    Ended,
    Unknown,
};

class IProcessInfoApi {
public:
    virtual ~IProcessInfoApi() = default;
    virtual std::optional<ProcessInfo> QueryProcess(std::uint32_t pid) = 0;
    virtual std::optional<std::uint64_t> QueryCreationTime(std::uint32_t pid) = 0;
    virtual ProcessProbeResult ProbeProcess(ProcessInstanceId id) = 0;
};

class ProcessInfoCache {
public:
    ProcessInfoCache();
    explicit ProcessInfoCache(IProcessInfoApi& process_api);

    ProcessInfo Resolve(std::uint32_t pid, std::uint64_t fallback_observation_id,
                        std::chrono::steady_clock::time_point now);
    ProcessProbeResult ProbeAlive(ProcessInstanceId id) const;
    bool RefreshAlive(ProcessInstanceId id) const;

private:
    struct CachedProcess {
        ProcessInfo info;
        std::uint8_t failed_creation_queries{};
        std::chrono::steady_clock::time_point last_validation;
    };

    struct FallbackEntry {
        ProcessInfo info;
        std::chrono::steady_clock::time_point last_attempt;
    };

    IProcessInfoApi& process_api_;
    std::unordered_map<std::uint32_t, CachedProcess> cache_;
    std::unordered_map<std::uint32_t, FallbackEntry> fallback_cache_;
};
