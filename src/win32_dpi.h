#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace win32_dpi {

inline constexpr UINT kDefaultDpi = 96;

inline int Scale(int value, UINT dpi) {
    return MulDiv(value, static_cast<int>(dpi), static_cast<int>(kDefaultDpi));
}

inline UINT System() {
    using GetDpiForSystemFunction = UINT(WINAPI*)();
    const HMODULE user32 = GetModuleHandleW(L"user32.dll");
    const auto get_dpi_for_system = reinterpret_cast<GetDpiForSystemFunction>(
        user32 == nullptr ? nullptr : GetProcAddress(user32, "GetDpiForSystem"));
    if (get_dpi_for_system != nullptr) {
        return get_dpi_for_system();
    }

    HDC screen = GetDC(nullptr);
    if (screen == nullptr) {
        return kDefaultDpi;
    }
    const UINT dpi = static_cast<UINT>(GetDeviceCaps(screen, LOGPIXELSX));
    ReleaseDC(nullptr, screen);
    return dpi == 0 ? kDefaultDpi : dpi;
}

inline UINT Window(HWND window) {
    using GetDpiForWindowFunction = UINT(WINAPI*)(HWND);
    const HMODULE user32 = GetModuleHandleW(L"user32.dll");
    const auto get_dpi_for_window = reinterpret_cast<GetDpiForWindowFunction>(
        user32 == nullptr ? nullptr : GetProcAddress(user32, "GetDpiForWindow"));
    return get_dpi_for_window == nullptr ? System() : get_dpi_for_window(window);
}

inline void AdjustWindowRect(RECT& rectangle, DWORD style, DWORD extended_style, UINT dpi) {
    using AdjustWindowRectExForDpiFunction = BOOL(WINAPI*)(LPRECT, DWORD, BOOL, DWORD, UINT);
    const HMODULE user32 = GetModuleHandleW(L"user32.dll");
    const auto adjust_for_dpi = reinterpret_cast<AdjustWindowRectExForDpiFunction>(
        user32 == nullptr ? nullptr : GetProcAddress(user32, "AdjustWindowRectExForDpi"));
    if (adjust_for_dpi == nullptr ||
        !adjust_for_dpi(&rectangle, style, FALSE, extended_style, dpi)) {
        AdjustWindowRectEx(&rectangle, style, FALSE, extended_style);
    }
}

}  // namespace win32_dpi
