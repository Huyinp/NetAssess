#include "single_instance.h"

#include <string>

SingleInstanceGuard::SingleInstanceGuard(std::wstring_view name) {
    const std::wstring terminated_name(name);
    SetLastError(ERROR_SUCCESS);
    mutex_ = CreateMutexW(nullptr, TRUE, terminated_name.c_str());
    if (mutex_ == nullptr) {
        error_ = GetLastError();
        return;
    }
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(mutex_);
        mutex_ = nullptr;
        error_ = ERROR_ALREADY_EXISTS;
    }
}

SingleInstanceGuard::~SingleInstanceGuard() {
    if (mutex_ != nullptr) {
        ReleaseMutex(mutex_);
        CloseHandle(mutex_);
    }
}

bool SingleInstanceGuard::acquired() const noexcept {
    return mutex_ != nullptr;
}

DWORD SingleInstanceGuard::error() const noexcept {
    return error_;
}
