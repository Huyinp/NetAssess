#pragma once

#include "traffic_types.h"

#include <cstdint>
#include <string>
#include <unordered_map>

struct ProcessInfo {
    ProcessInstanceId id;
    std::wstring name;
    bool alive{};
};

class ProcessInfoCache {
public:
    ProcessInfo Resolve(std::uint32_t pid, std::uint64_t fallback_observation_id);
    bool RefreshAlive(ProcessInstanceId id) const;

private:
    std::unordered_map<std::uint32_t, ProcessInfo> cache_;
};
