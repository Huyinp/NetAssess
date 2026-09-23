#pragma once

#include "traffic_types.h"

#include <memory>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>

struct ProcessActionResult {
    bool succeeded;
    DWORD error;
};

class IProcessActionApi {
public:
    virtual ~IProcessActionApi() = default;

    virtual HANDLE OpenProcess(DWORD desired_access, BOOL inherit_handle, DWORD process_id) = 0;
    virtual BOOL GetProcessTimes(HANDLE process, FILETIME* creation_time, FILETIME* exit_time,
                                 FILETIME* kernel_time, FILETIME* user_time) = 0;
    virtual BOOL QueryFullProcessImageNameW(HANDLE process, DWORD flags, LPWSTR path,
                                            PDWORD path_length) = 0;
    virtual BOOL ShellExecuteExW(SHELLEXECUTEINFOW* execute_info) = 0;
    virtual BOOL TerminateProcess(HANDLE process, UINT exit_code) = 0;
    virtual BOOL CloseHandle(HANDLE handle) = 0;
    virtual DWORD LastError() const = 0;
};

class ProcessActions {
public:
    ProcessActions();
    explicit ProcessActions(IProcessActionApi& api);

    ProcessActionResult RevealExecutable(ProcessInstanceId process);
    ProcessActionResult Terminate(ProcessInstanceId process);

private:
    std::unique_ptr<IProcessActionApi> owned_api_;
    IProcessActionApi& api_;
};
