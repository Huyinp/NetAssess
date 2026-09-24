#pragma once

#include <string_view>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

class SingleInstanceGuard {
public:
    explicit SingleInstanceGuard(
        std::wstring_view name = L"Global\\NetAssess-8F0F9E61-6F72-4D5C-899F-36653539581D");
    ~SingleInstanceGuard();

    SingleInstanceGuard(const SingleInstanceGuard&) = delete;
    SingleInstanceGuard& operator=(const SingleInstanceGuard&) = delete;

    bool acquired() const noexcept;
    DWORD error() const noexcept;

private:
    HANDLE mutex_{};
    DWORD error_{};
};
