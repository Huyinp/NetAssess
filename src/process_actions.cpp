#include "process_actions.h"

#include <cstdint>
#include <string>
#include <string_view>

namespace {

class WindowsProcessActionApi final : public IProcessActionApi {
public:
    HANDLE OpenProcess(DWORD desired_access, BOOL inherit_handle, DWORD process_id) override {
        return ::OpenProcess(desired_access, inherit_handle, process_id);
    }

    BOOL GetProcessTimes(HANDLE process, FILETIME* creation_time, FILETIME* exit_time,
                         FILETIME* kernel_time, FILETIME* user_time) override {
        return ::GetProcessTimes(process, creation_time, exit_time, kernel_time, user_time);
    }

    BOOL QueryFullProcessImageNameW(HANDLE process, DWORD flags, LPWSTR path,
                                    PDWORD path_length) override {
        return ::QueryFullProcessImageNameW(process, flags, path, path_length);
    }

    BOOL ShellExecuteExW(SHELLEXECUTEINFOW* execute_info) override {
        return ::ShellExecuteExW(execute_info);
    }

    BOOL TerminateProcess(HANDLE process, UINT exit_code) override {
        return ::TerminateProcess(process, exit_code);
    }

    BOOL CloseHandle(HANDLE handle) override { return ::CloseHandle(handle); }

    DWORD LastError() const override { return ::GetLastError(); }
};

class ProcessHandle {
public:
    ProcessHandle(IProcessActionApi& api, HANDLE handle) : api_(api), handle_(handle) {}
    ~ProcessHandle() {
        if (handle_ != nullptr) {
            api_.CloseHandle(handle_);
        }
    }

    ProcessHandle(const ProcessHandle&) = delete;
    ProcessHandle& operator=(const ProcessHandle&) = delete;

private:
    IProcessActionApi& api_;
    HANDLE handle_;
};

ProcessActionResult Failure(DWORD error) {
    return {false, error == ERROR_SUCCESS ? ERROR_GEN_FAILURE : error};
}

std::uint64_t FileTimeValue(const FILETIME& value) {
    return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
}

bool MatchesProcessInstance(IProcessActionApi& api, HANDLE process,
                            ProcessInstanceId expected, DWORD& error) {
    FILETIME creation_time{};
    FILETIME exit_time{};
    FILETIME kernel_time{};
    FILETIME user_time{};
    if (!api.GetProcessTimes(process, &creation_time, &exit_time, &kernel_time, &user_time)) {
        error = api.LastError();
        return false;
    }
    if (FileTimeValue(creation_time) != expected.creation_time_100ns) {
        error = ERROR_NOT_FOUND;
        return false;
    }
    return true;
}

std::wstring QuoteWindowsArgument(std::wstring_view value) {
    std::wstring quoted;
    quoted.reserve(value.size() + 2);
    quoted.push_back(L'"');

    std::size_t backslash_count{};
    for (const wchar_t character : value) {
        if (character == L'\\') {
            ++backslash_count;
            continue;
        }
        if (character == L'"') {
            quoted.append(backslash_count * 2 + 1, L'\\');
        } else {
            quoted.append(backslash_count, L'\\');
        }
        quoted.push_back(character);
        backslash_count = 0;
    }
    quoted.append(backslash_count * 2, L'\\');
    quoted.push_back(L'"');
    return quoted;
}

}  // namespace

ProcessActions::ProcessActions()
    : owned_api_(std::make_unique<WindowsProcessActionApi>()), api_(*owned_api_) {}

ProcessActions::ProcessActions(IProcessActionApi& api) : api_(api) {}

ProcessActionResult ProcessActions::RevealExecutable(ProcessInstanceId process) {
    HANDLE handle = api_.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process.pid);
    if (handle == nullptr) {
        return Failure(api_.LastError());
    }
    ProcessHandle process_handle(api_, handle);

    DWORD error{};
    if (!MatchesProcessInstance(api_, handle, process, error)) {
        return Failure(error);
    }

    std::wstring image_path(32768, L'\0');
    DWORD image_path_length = static_cast<DWORD>(image_path.size());
    if (!api_.QueryFullProcessImageNameW(handle, 0, image_path.data(), &image_path_length)) {
        return Failure(api_.LastError());
    }
    image_path.resize(image_path_length);

    const std::wstring parameters = L"/select," + QuoteWindowsArgument(image_path);
    SHELLEXECUTEINFOW execute_info{};
    execute_info.cbSize = sizeof(execute_info);
    execute_info.fMask = SEE_MASK_FLAG_NO_UI;
    execute_info.lpFile = L"explorer.exe";
    execute_info.lpParameters = parameters.c_str();
    execute_info.nShow = SW_SHOWNORMAL;
    if (!api_.ShellExecuteExW(&execute_info)) {
        return Failure(api_.LastError());
    }
    return {true, ERROR_SUCCESS};
}

ProcessActionResult ProcessActions::Terminate(ProcessInstanceId process) {
    constexpr DWORD desired_access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE;
    HANDLE handle = api_.OpenProcess(desired_access, FALSE, process.pid);
    if (handle == nullptr) {
        return Failure(api_.LastError());
    }
    ProcessHandle process_handle(api_, handle);

    DWORD error{};
    if (!MatchesProcessInstance(api_, handle, process, error)) {
        return Failure(error);
    }
    if (!api_.TerminateProcess(handle, 1)) {
        return Failure(api_.LastError());
    }
    return {true, ERROR_SUCCESS};
}
