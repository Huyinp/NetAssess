#include "process_info.h"

#include <optional>
#include <string>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace {

std::uint64_t FileTimeValue(const FILETIME& value) {
    return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32) |
           value.dwLowDateTime;
}

std::optional<std::uint64_t> ProcessCreationTime(HANDLE process) {
    FILETIME creation_time{};
    FILETIME exit_time{};
    FILETIME kernel_time{};
    FILETIME user_time{};
    if (!GetProcessTimes(process, &creation_time, &exit_time, &kernel_time, &user_time)) {
        return std::nullopt;
    }
    return FileTimeValue(creation_time);
}

std::optional<ProcessInfo> QueryWindowsProcess(std::uint32_t pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == nullptr) {
        return std::nullopt;
    }

    const auto creation_time = ProcessCreationTime(process);
    std::wstring image_path(32768, L'\0');
    DWORD image_path_length = static_cast<DWORD>(image_path.size());
    const bool got_image_path = QueryFullProcessImageNameW(
        process, 0, image_path.data(), &image_path_length) != FALSE;
    CloseHandle(process);
    if (!creation_time || !got_image_path) {
        return std::nullopt;
    }

    image_path.resize(image_path_length);
    const auto name_start = image_path.find_last_of(L"\\\\/");
    const std::wstring name = name_start == std::wstring::npos
                                  ? image_path
                                  : image_path.substr(name_start + 1);
    if (name.empty()) {
        return std::nullopt;
    }
    return ProcessInfo{{pid, *creation_time}, name, true};
}

std::optional<std::uint64_t> QueryWindowsCreationTime(std::uint32_t pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == nullptr) {
        return std::nullopt;
    }

    const auto creation_time = ProcessCreationTime(process);
    CloseHandle(process);
    return creation_time;
}

ProcessInfo FallbackProcess(std::uint32_t pid, std::uint64_t fallback_observation_id) {
    return {{pid, fallback_observation_id}, L"受限进程 (" + std::to_wstring(pid) + L")", false};
}

class WindowsProcessInfoApi final : public IProcessInfoApi {
public:
    std::optional<ProcessInfo> QueryProcess(std::uint32_t pid) override {
        return QueryWindowsProcess(pid);
    }

    std::optional<std::uint64_t> QueryCreationTime(std::uint32_t pid) override {
        return QueryWindowsCreationTime(pid);
    }
};

IProcessInfoApi& DefaultProcessInfoApi() {
    static WindowsProcessInfoApi api;
    return api;
}

}  // namespace

ProcessInfoCache::ProcessInfoCache() : ProcessInfoCache(DefaultProcessInfoApi()) {}

ProcessInfoCache::ProcessInfoCache(IProcessInfoApi& process_api) : process_api_(process_api) {}

ProcessInfo ProcessInfoCache::Resolve(std::uint32_t pid,
                                      std::uint64_t fallback_observation_id,
                                      std::chrono::steady_clock::time_point now) {
    auto cached = cache_.find(pid);
    if (cached != cache_.end()) {
        if (now - cached->second.last_validation < std::chrono::seconds(1)) {
            return cached->second.info;
        }
        cached->second.last_validation = now;
        const auto creation_time = process_api_.QueryCreationTime(pid);
        if (creation_time &&
            *creation_time == cached->second.info.id.creation_time_100ns) {
            cached->second.failed_creation_queries = 0;
            return cached->second.info;
        }
        if (!creation_time && ++cached->second.failed_creation_queries < 8) {
            return cached->second.info;
        }

        const auto process = process_api_.QueryProcess(pid);
        if (process) {
            cached->second = {*process, 0, now};
            return *process;
        }
        cache_.erase(cached);
        auto [fallback, inserted] = fallback_cache_.try_emplace(
            pid, FallbackEntry{FallbackProcess(pid, fallback_observation_id), now});
        if (!inserted) {
            fallback->second = {FallbackProcess(pid, fallback_observation_id), now};
        }
        return fallback->second.info;
    }

    auto fallback = fallback_cache_.find(pid);
    if (fallback != fallback_cache_.end() &&
        now - fallback->second.last_attempt < std::chrono::seconds(1)) {
        return fallback->second.info;
    }

    const auto process = process_api_.QueryProcess(pid);
    if (process) {
        fallback_cache_.erase(pid);
        cache_[pid] = {*process, 0, now};
        return *process;
    }

    if (fallback == fallback_cache_.end()) {
        fallback = fallback_cache_
                       .try_emplace(pid,
                                    FallbackEntry{FallbackProcess(pid, fallback_observation_id),
                                                  now})
                       .first;
    } else {
        fallback->second.last_attempt = now;
    }
    return fallback->second.info;
}

bool ProcessInfoCache::RefreshAlive(ProcessInstanceId id) const {
    const auto creation_time = process_api_.QueryCreationTime(id.pid);
    return creation_time && *creation_time == id.creation_time_100ns;
}
