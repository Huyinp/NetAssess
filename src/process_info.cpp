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

std::optional<ProcessInfo> QueryProcess(std::uint32_t pid) {
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

std::optional<std::uint64_t> QueryCreationTime(std::uint32_t pid) {
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

}  // namespace

ProcessInfo ProcessInfoCache::Resolve(std::uint32_t pid,
                                      std::uint64_t fallback_observation_id) {
    const auto process = QueryProcess(pid);
    if (!process) {
        return FallbackProcess(pid, fallback_observation_id);
    }

    const auto cached = cache_.find(pid);
    if (cached != cache_.end() &&
        cached->second.id.creation_time_100ns == process->id.creation_time_100ns) {
        return cached->second;
    }

    cache_[pid] = *process;
    return *process;
}

bool ProcessInfoCache::RefreshAlive(ProcessInstanceId id) const {
    const auto creation_time = QueryCreationTime(id.pid);
    return creation_time && *creation_time == id.creation_time_100ns;
}
