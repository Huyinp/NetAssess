#pragma once

#include "traffic_types.h"

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

struct ProcessInfo {
    ProcessInstanceId id;
    std::wstring name;
    bool alive{};
};

class IProcessInfoApi {
public:
    virtual ~IProcessInfoApi() = default;
    virtual std::optional<ProcessInfo> QueryProcess(std::uint32_t pid) = 0;
    virtual std::optional<std::uint64_t> QueryCreationTime(std::uint32_t pid) = 0;
};

class ProcessInfoCache {
public:
    ProcessInfoCache();
    explicit ProcessInfoCache(IProcessInfoApi& process_api);

    ProcessInfo Resolve(std::uint32_t pid, std::uint64_t fallback_observation_id);
    bool RefreshAlive(ProcessInstanceId id) const;

private:
    IProcessInfoApi& process_api_;
    std::unordered_map<std::uint32_t, ProcessInfo> cache_;
    std::unordered_map<std::uint32_t, ProcessInfo> fallback_cache_;
};
