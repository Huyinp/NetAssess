#include "main_window.h"

#include "connection_aggregator.h"
#include "etw_monitor.h"
#include "process_info.h"
#include "traffic_aggregator.h"

#include <commctrl.h>

namespace {

void EnableBestDpiAwareness() {
    const HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (user32 == nullptr) {
        return;
    }

    using SetProcessDpiAwarenessContextFunction = BOOL(WINAPI*)(HANDLE);
    const auto set_dpi_context = reinterpret_cast<SetProcessDpiAwarenessContextFunction>(
        GetProcAddress(user32, "SetProcessDpiAwarenessContext"));
    if (set_dpi_context != nullptr &&
        set_dpi_context(reinterpret_cast<HANDLE>(static_cast<INT_PTR>(-4)))) {
        return;
    }

    const HMODULE shcore = LoadLibraryW(L"shcore.dll");
    if (shcore != nullptr) {
        using SetProcessDpiAwarenessFunction = HRESULT(WINAPI*)(int);
        const auto set_dpi_awareness = reinterpret_cast<SetProcessDpiAwarenessFunction>(
            GetProcAddress(shcore, "SetProcessDpiAwareness"));
        if (set_dpi_awareness != nullptr && SUCCEEDED(set_dpi_awareness(2))) {
            FreeLibrary(shcore);
            return;
        }
        FreeLibrary(shcore);
    }

    using SetProcessDpiAwareFunction = BOOL(WINAPI*)();
    const auto set_dpi_aware = reinterpret_cast<SetProcessDpiAwareFunction>(
        GetProcAddress(user32, "SetProcessDPIAware"));
    if (set_dpi_aware != nullptr) {
        set_dpi_aware();
    }
}

}  // namespace

int APIENTRY wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show_command) {
    EnableBestDpiAwareness();

    INITCOMMONCONTROLSEX controls{};
    controls.dwSize = sizeof(controls);
    controls.dwICC = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES;
    if (!InitCommonControlsEx(&controls)) {
        MessageBoxW(nullptr, L"无法初始化 Windows 公共控件。", L"NetAssess",
                    MB_OK | MB_ICONERROR);
        return 1;
    }

    TrafficAggregator traffic_aggregator;
    ConnectionAggregator connection_aggregator;
    ProcessInfoCache process_cache;
    EtwMonitor monitor(traffic_aggregator, connection_aggregator, process_cache);
    HWND window = CreateMainWindow(instance, traffic_aggregator,
                                   connection_aggregator, process_cache, monitor);
    if (window == nullptr) {
        MessageBoxW(nullptr, L"无法创建主窗口。", L"NetAssess", MB_OK | MB_ICONERROR);
        return 1;
    }

    ShowWindow(window, show_command);
    UpdateWindow(window);
    StartMainWindowCollection(window);

    MSG message{};
    int get_message_result{};
    while ((get_message_result = GetMessageW(&message, nullptr, 0, 0)) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    monitor.Stop();
    return get_message_result == -1 ? 1 : static_cast<int>(message.wParam);
}
