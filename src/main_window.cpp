#include "main_window.h"

#include "etw_monitor.h"
#include "process_info.h"
#include "protocol_classifier.h"
#include "traffic_aggregator.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cwctype>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>

#include <commctrl.h>

namespace {

constexpr wchar_t kWindowClassName[] = L"NetAssessMainWindow";
constexpr UINT_PTR kRefreshTimerId = 1;
constexpr UINT kStartCollectionMessage = WM_APP + 1;
constexpr int kStartStopButtonId = 1001;
constexpr int kClearButtonId = 1002;
constexpr int kFilterEditId = 1003;
constexpr UINT kDefaultDpi = 96;

int ScaleForDpi(int value, UINT dpi) {
    return MulDiv(value, static_cast<int>(dpi), static_cast<int>(kDefaultDpi));
}

UINT SystemDpi() {
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

UINT WindowDpi(HWND window) {
    using GetDpiForWindowFunction = UINT(WINAPI*)(HWND);
    const HMODULE user32 = GetModuleHandleW(L"user32.dll");
    const auto get_dpi_for_window = reinterpret_cast<GetDpiForWindowFunction>(
        user32 == nullptr ? nullptr : GetProcAddress(user32, "GetDpiForWindow"));
    if (get_dpi_for_window != nullptr) {
        return get_dpi_for_window(window);
    }
    return SystemDpi();
}

void AdjustWindowRectForDpi(RECT& rectangle, DWORD style, DWORD extended_style, UINT dpi) {
    using AdjustWindowRectExForDpiFunction = BOOL(WINAPI*)(LPRECT, DWORD, BOOL, DWORD, UINT);
    const HMODULE user32 = GetModuleHandleW(L"user32.dll");
    const auto adjust_for_dpi = reinterpret_cast<AdjustWindowRectExForDpiFunction>(
        user32 == nullptr ? nullptr : GetProcAddress(user32, "AdjustWindowRectExForDpi"));
    if (adjust_for_dpi == nullptr ||
        !adjust_for_dpi(&rectangle, style, FALSE, extended_style, dpi)) {
        AdjustWindowRectEx(&rectangle, style, FALSE, extended_style);
    }
}

bool ContainsCaseInsensitive(std::wstring_view value, std::wstring_view filter) {
    if (filter.empty()) {
        return true;
    }
    return FindStringOrdinal(FIND_FROMSTART, value.data(), static_cast<int>(value.size()),
                             filter.data(), static_cast<int>(filter.size()), TRUE) >= 0;
}

SortColumn SortColumnForListColumn(int column) {
    constexpr std::array columns{
        SortColumn::ProcessName, SortColumn::Pid,          SortColumn::Status,
        SortColumn::Transport,   SortColumn::ApplicationProtocol,
        SortColumn::SentBytes,   SortColumn::SentRate,     SortColumn::ReceivedBytes,
        SortColumn::ReceivedRate,
    };
    return column >= 0 && column < static_cast<int>(columns.size())
               ? columns[static_cast<std::size_t>(column)]
               : SortColumn::CombinedSpeed;
}

std::wstring SystemErrorText(ULONG error) {
    if (error == ERROR_SUCCESS) {
        return L"无";
    }

    wchar_t buffer[512]{};
    const DWORD length = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM |
                                            FORMAT_MESSAGE_IGNORE_INSERTS,
                                        nullptr, error, 0, buffer,
                                        static_cast<DWORD>(std::size(buffer)), nullptr);
    std::wstring message = length == 0 ? L"未知错误" : std::wstring(buffer, length);
    while (!message.empty() && std::iswspace(message.back())) {
        message.pop_back();
    }
    return L"错误 " + std::to_wstring(error) + L"（" + message + L"）";
}

class MainWindow {
public:
    MainWindow(TrafficAggregator& aggregator, ProcessInfoCache& process_cache,
               EtwMonitor& monitor)
        : aggregator_(aggregator), process_cache_(process_cache), monitor_(monitor) {}

    static LRESULT CALLBACK WindowProcedure(HWND window, UINT message, WPARAM wparam,
                                            LPARAM lparam) {
        MainWindow* self = reinterpret_cast<MainWindow*>(
            GetWindowLongPtrW(window, GWLP_USERDATA));
        if (message == WM_NCCREATE) {
            auto* create = reinterpret_cast<CREATESTRUCTW*>(lparam);
            auto* context = static_cast<CreationContext*>(create->lpCreateParams);
            self = context->window;
            context->attached = true;
            self->window_ = window;
            SetWindowLongPtrW(window, GWLP_USERDATA,
                              reinterpret_cast<LONG_PTR>(self));
        }

        const LRESULT result = self == nullptr
                                   ? DefWindowProcW(window, message, wparam, lparam)
                                   : self->HandleMessage(message, wparam, lparam);
        if (message == WM_NCDESTROY && self != nullptr) {
            SetWindowLongPtrW(window, GWLP_USERDATA, 0);
            delete self;
        }
        return result;
    }

    struct CreationContext {
        MainWindow* window;
        bool attached{};
    };

private:
    LRESULT HandleMessage(UINT message, WPARAM wparam, LPARAM lparam) {
        switch (message) {
        case WM_CREATE:
            dpi_ = WindowDpi(window_);
            if (!CreateControls()) {
                return -1;
            }
            refresh_timer_ = SetTimer(window_, kRefreshTimerId, 1000, nullptr);
            if (refresh_timer_ == 0) {
                return -1;
            }
            RefreshSnapshot();
            return 0;
        case WM_COMMAND:
            HandleCommand(LOWORD(wparam), HIWORD(wparam));
            return 0;
        case WM_NOTIFY:
            HandleNotify(reinterpret_cast<NMHDR*>(lparam));
            return 0;
        case WM_TIMER:
            if (wparam == kRefreshTimerId) {
                RefreshSnapshot();
            }
            return 0;
        case WM_SIZE:
            LayoutControls();
            return 0;
        case WM_GETMINMAXINFO: {
            auto* sizing = reinterpret_cast<MINMAXINFO*>(lparam);
            sizing->ptMinTrackSize.x = ScaleForDpi(760, dpi_);
            sizing->ptMinTrackSize.y = ScaleForDpi(420, dpi_);
            return 0;
        }
        case WM_DPICHANGED: {
            dpi_ = HIWORD(wparam);
            const auto* suggested = reinterpret_cast<RECT*>(lparam);
            SetWindowPos(window_, nullptr, suggested->left, suggested->top,
                         suggested->right - suggested->left,
                         suggested->bottom - suggested->top,
                         SWP_NOACTIVATE | SWP_NOZORDER);
            LayoutControls();
            return 0;
        }
        case kStartCollectionMessage: {
            const bool started = monitor_.Start();
            UpdateStatus();
            return started ? TRUE : FALSE;
        }
        case WM_DESTROY:
            if (refresh_timer_ != 0) {
                KillTimer(window_, refresh_timer_);
                refresh_timer_ = 0;
            }
            monitor_.Stop();
            PostQuitMessage(0);
            return 0;
        default:
            return DefWindowProcW(window_, message, wparam, lparam);
        }
    }

    bool CreateControls() {
        const DWORD child_style = WS_CHILD | WS_VISIBLE;
        start_stop_button_ = CreateWindowExW(
            0, L"BUTTON", L"开始采集", child_style | BS_PUSHBUTTON,
            0, 0, 0, 0, window_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(kStartStopButtonId)),
            GetModuleHandleW(nullptr), nullptr);
        clear_button_ = CreateWindowExW(
            0, L"BUTTON", L"清零统计", child_style | BS_PUSHBUTTON,
            0, 0, 0, 0, window_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(kClearButtonId)),
            GetModuleHandleW(nullptr), nullptr);
        filter_label_ = CreateWindowExW(
            0, L"STATIC", L"进程名筛选：", child_style | SS_CENTERIMAGE,
            0, 0, 0, 0, window_, nullptr, GetModuleHandleW(nullptr), nullptr);
        filter_edit_ = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"EDIT", L"", child_style | ES_AUTOHSCROLL,
            0, 0, 0, 0, window_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(kFilterEditId)),
            GetModuleHandleW(nullptr), nullptr);
        list_view_ = CreateWindowExW(
            WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
            child_style | LVS_REPORT | LVS_SHOWSELALWAYS,
            0, 0, 0, 0, window_, nullptr, GetModuleHandleW(nullptr), nullptr);
        status_bar_ = CreateWindowExW(
            0, STATUSCLASSNAMEW, L"", child_style | SBARS_SIZEGRIP,
            0, 0, 0, 0, window_, nullptr, GetModuleHandleW(nullptr), nullptr);
        if (start_stop_button_ == nullptr || clear_button_ == nullptr ||
            filter_label_ == nullptr || filter_edit_ == nullptr ||
            list_view_ == nullptr || status_bar_ == nullptr) {
            return false;
        }

        const HFONT font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
        for (HWND control : {start_stop_button_, clear_button_, filter_label_,
                             filter_edit_, list_view_, status_bar_}) {
            SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        }
        ListView_SetExtendedListViewStyleEx(
            list_view_, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);

        constexpr std::array<std::wstring_view, 9> column_names{
            L"进程名", L"PID", L"状态", L"传输层协议", L"推断应用协议",
            L"上行累计", L"上行速度", L"下行累计", L"下行速度",
        };
        constexpr std::array<int, 9> column_widths{190, 72, 72, 92, 170,
                                                   105, 105, 105, 105};
        for (int index = 0; index < static_cast<int>(column_names.size()); ++index) {
            LVCOLUMNW column{};
            column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
            column.pszText = const_cast<wchar_t*>(
                column_names[static_cast<std::size_t>(index)].data());
            column.cx = ScaleForDpi(column_widths[static_cast<std::size_t>(index)], dpi_);
            column.iSubItem = index;
            if (ListView_InsertColumn(list_view_, index, &column) == -1) {
                return false;
            }
        }
        LayoutControls();
        return true;
    }

    void LayoutControls() {
        if (status_bar_ == nullptr) {
            return;
        }
        RECT client{};
        GetClientRect(window_, &client);
        SendMessageW(status_bar_, WM_SIZE, 0, 0);
        RECT status_rectangle{};
        GetWindowRect(status_bar_, &status_rectangle);
        const int status_height = status_rectangle.bottom - status_rectangle.top;
        const int margin = ScaleForDpi(8, dpi_);
        const int control_height = ScaleForDpi(28, dpi_);
        const int button_width = ScaleForDpi(100, dpi_);
        const int gap = ScaleForDpi(8, dpi_);
        const int label_width = ScaleForDpi(92, dpi_);
        const int top = margin;

        int left = margin;
        MoveWindow(start_stop_button_, left, top, button_width, control_height, TRUE);
        left += button_width + gap;
        MoveWindow(clear_button_, left, top, button_width, control_height, TRUE);
        left += button_width + gap;
        MoveWindow(filter_label_, left, top, label_width, control_height, TRUE);
        left += label_width;
        MoveWindow(filter_edit_, left, top,
                   std::max(0, static_cast<int>(client.right) - margin - left),
                   control_height, TRUE);

        const int list_top = top + control_height + margin;
        MoveWindow(list_view_, margin, list_top,
                   std::max(0, static_cast<int>(client.right) - margin * 2),
                   std::max(0, static_cast<int>(client.bottom) - status_height -
                                   margin - list_top),
                   TRUE);
    }

    void HandleCommand(int control_id, int notification) {
        if (control_id == kStartStopButtonId && notification == BN_CLICKED) {
            if (monitor_.running()) {
                monitor_.Stop();
            } else {
                monitor_.Start();
            }
            UpdateStatus();
        } else if (control_id == kClearButtonId && notification == BN_CLICKED) {
            aggregator_.Clear();
            last_snapshot_.clear();
            RefreshRows();
            UpdateStatus();
        } else if (control_id == kFilterEditId && notification == EN_CHANGE) {
            RefreshRows();
        }
    }

    void HandleNotify(const NMHDR* notification) {
        if (notification == nullptr || notification->hwndFrom != list_view_ ||
            notification->code != LVN_COLUMNCLICK) {
            return;
        }
        const auto* column_click = reinterpret_cast<const NMLISTVIEW*>(notification);
        const SortColumn clicked_column = SortColumnForListColumn(column_click->iSubItem);
        if (sort_column_ == clicked_column) {
            ascending_ = !ascending_;
        } else {
            sort_column_ = clicked_column;
            ascending_ = true;
        }
        RefreshRows();
    }

    std::wstring FilterText() const {
        const int length = GetWindowTextLengthW(filter_edit_);
        std::wstring filter(static_cast<std::size_t>(length) + 1, L'\0');
        if (length != 0) {
            GetWindowTextW(filter_edit_, filter.data(), length + 1);
        }
        filter.resize(static_cast<std::size_t>(length));
        return filter;
    }

    void RefreshSnapshot() {
        last_snapshot_ = aggregator_.Snapshot(std::chrono::steady_clock::now());
        RefreshRows();
        UpdateStatus();
    }

    void RefreshRows() {
        if (list_view_ == nullptr) {
            return;
        }
        const std::wstring filter = FilterText();
        const auto rows = BuildVisibleRows(
            last_snapshot_, filter, sort_column_, ascending_,
            [this](ProcessInstanceId process) {
                return process_cache_.RefreshAlive(process);
            });

        const std::set<TrafficKey> selected_keys = SelectedKeys();
        const ScrollAnchor scroll_anchor = CaptureScrollAnchor();
        ReconcileRowStructure(rows);
        for (int index = 0; index < static_cast<int>(rows.size()); ++index) {
            UpdateRow(index, rows[static_cast<std::size_t>(index)]);
        }
        RestoreSelection(selected_keys);
        RestoreScrollAnchor(scroll_anchor);
    }

    std::set<TrafficKey> SelectedKeys() const {
        std::set<TrafficKey> selected;
        for (int index = 0; index < static_cast<int>(current_keys_.size()); ++index) {
            if ((ListView_GetItemState(list_view_, index, LVIS_SELECTED) & LVIS_SELECTED) != 0) {
                selected.insert(current_keys_[static_cast<std::size_t>(index)]);
            }
        }
        return selected;
    }

    struct ScrollAnchor {
        std::optional<TrafficKey> key;
        int previous_top{};
    };

    ScrollAnchor CaptureScrollAnchor() const {
        const int top = ListView_GetTopIndex(list_view_);
        if (top >= 0 && top < static_cast<int>(current_keys_.size())) {
            return {current_keys_[static_cast<std::size_t>(top)], top};
        }
        return {std::nullopt, top};
    }

    void ReconcileRowStructure(const std::vector<TrafficDisplayRow>& rows) {
        std::set<TrafficKey> desired_keys;
        for (const TrafficDisplayRow& row : rows) {
            desired_keys.insert(row.traffic.key);
        }

        for (int index = static_cast<int>(current_keys_.size()) - 1; index >= 0; --index) {
            if (!desired_keys.contains(current_keys_[static_cast<std::size_t>(index)])) {
                if (ListView_DeleteItem(list_view_, index)) {
                    current_keys_.erase(current_keys_.begin() + index);
                }
            }
        }
        RebuildRowMap();

        for (int target = 0; target < static_cast<int>(rows.size()); ++target) {
            const TrafficKey& key = rows[static_cast<std::size_t>(target)].traffic.key;
            const auto existing = row_map_.find(key);
            if (existing == row_map_.end()) {
                if (InsertBlankRow(target)) {
                    current_keys_.insert(current_keys_.begin() + target, key);
                    RebuildRowMap();
                }
            } else if (existing->second != target) {
                const int source = existing->second;
                if (ListView_DeleteItem(list_view_, source)) {
                    current_keys_.erase(current_keys_.begin() + source);
                    if (InsertBlankRow(target)) {
                        current_keys_.insert(current_keys_.begin() + target, key);
                    }
                    RebuildRowMap();
                }
            }
        }
    }

    bool InsertBlankRow(int index) const {
        wchar_t blank[] = L"";
        LVITEMW item{};
        item.mask = LVIF_TEXT;
        item.iItem = index;
        item.pszText = blank;
        return ListView_InsertItem(list_view_, &item) != -1;
    }

    void RebuildRowMap() {
        row_map_.clear();
        for (int index = 0; index < static_cast<int>(current_keys_.size()); ++index) {
            row_map_.emplace(current_keys_[static_cast<std::size_t>(index)], index);
        }
    }

    void UpdateRow(int index, const TrafficDisplayRow& row) const {
        const TrafficSnapshot& traffic = row.traffic;
        SetItemText(index, 0, traffic.process_name);
        SetItemText(index, 1, std::to_wstring(traffic.key.process.pid));
        SetItemText(index, 2, ProcessStatusText(row.process_alive));
        SetItemText(index, 3, std::wstring{TransportProtocolName(traffic.key.transport)});
        SetItemText(index, 4, ApplicationProtocolName(traffic.key.application_protocol));
        SetItemText(index, 5, FormatBytes(traffic.sent_bytes));
        SetItemText(index, 6, FormatRate(traffic.sent_bytes_per_second));
        SetItemText(index, 7, FormatBytes(traffic.received_bytes));
        SetItemText(index, 8, FormatRate(traffic.received_bytes_per_second));
    }

    void SetItemText(int row, int column, std::wstring_view text) const {
        std::wstring value{text};
        LVITEMW item{};
        item.iSubItem = column;
        item.pszText = value.data();
        SendMessageW(list_view_, LVM_SETITEMTEXTW, row,
                     reinterpret_cast<LPARAM>(&item));
    }

    void RestoreSelection(const std::set<TrafficKey>& selected_keys) const {
        ListView_SetItemState(list_view_, -1, 0, LVIS_SELECTED);
        for (const TrafficKey& key : selected_keys) {
            const auto row = row_map_.find(key);
            if (row != row_map_.end()) {
                ListView_SetItemState(list_view_, row->second, LVIS_SELECTED, LVIS_SELECTED);
            }
        }
    }

    void RestoreScrollAnchor(const ScrollAnchor& anchor) const {
        const int count = ListView_GetItemCount(list_view_);
        if (count == 0) {
            return;
        }
        int target = std::min(anchor.previous_top, count - 1);
        if (anchor.key) {
            const auto row = row_map_.find(*anchor.key);
            if (row != row_map_.end()) {
                target = row->second;
            }
        }
        ListView_EnsureVisible(list_view_, target, FALSE);
        RECT item_rectangle{};
        if (ListView_GetItemRect(list_view_, 0, &item_rectangle, LVIR_BOUNDS)) {
            const int current_top = ListView_GetTopIndex(list_view_);
            ListView_Scroll(list_view_, 0,
                            (target - current_top) *
                                (item_rectangle.bottom - item_rectangle.top));
        }
    }

    void UpdateStatus() const {
        if (status_bar_ == nullptr) {
            return;
        }
        const bool running = monitor_.running();
        const EtwLossCounters loss_counters = monitor_.loss_counters();
        SetWindowTextW(start_stop_button_, running ? L"停止采集" : L"开始采集");
        const std::wstring status =
            std::wstring(L"采集状态：") + (running ? L"运行中" : L"已停止") +
            L"  |  事件丢失：" + std::to_wstring(loss_counters.events_lost) +
            L"  |  实时缓冲区丢失：" +
                std::to_wstring(loss_counters.real_time_buffers_lost) +
            L"  |  解析失败：" + std::to_wstring(monitor_.parse_failures()) +
            L"  |  最近错误：" + SystemErrorText(monitor_.last_error());
        SendMessageW(status_bar_, SB_SETTEXTW, 0,
                     reinterpret_cast<LPARAM>(status.c_str()));
    }

    TrafficAggregator& aggregator_;
    ProcessInfoCache& process_cache_;
    EtwMonitor& monitor_;
    HWND window_{};
    HWND start_stop_button_{};
    HWND clear_button_{};
    HWND filter_label_{};
    HWND filter_edit_{};
    HWND list_view_{};
    HWND status_bar_{};
    UINT dpi_{kDefaultDpi};
    UINT_PTR refresh_timer_{};
    SortColumn sort_column_{SortColumn::CombinedSpeed};
    bool ascending_{};
    std::vector<TrafficSnapshot> last_snapshot_;
    std::vector<TrafficKey> current_keys_;
    std::map<TrafficKey, int> row_map_;
};

bool RegisterWindowClass(HINSTANCE instance) {
    WNDCLASSEXW window_class{};
    window_class.cbSize = sizeof(window_class);
    window_class.style = CS_HREDRAW | CS_VREDRAW;
    window_class.lpfnWndProc = MainWindow::WindowProcedure;
    window_class.hInstance = instance;
    window_class.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    window_class.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    window_class.lpszClassName = kWindowClassName;
    window_class.hIconSm = window_class.hIcon;
    return RegisterClassExW(&window_class) != 0 ||
           GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
}

}  // namespace

std::vector<TrafficDisplayRow> BuildVisibleRows(
    const std::vector<TrafficSnapshot>& snapshots, std::wstring_view filter,
    SortColumn sort_column, bool ascending,
    const std::function<bool(ProcessInstanceId)>& alive_lookup) {
    std::vector<TrafficDisplayRow> rows;
    rows.reserve(snapshots.size());
    for (const TrafficSnapshot& snapshot : snapshots) {
        if (ContainsCaseInsensitive(snapshot.process_name, filter)) {
            rows.push_back({snapshot, alive_lookup(snapshot.key.process)});
        }
    }
    SortTrafficRows(rows, sort_column, ascending);
    return rows;
}

HWND CreateMainWindow(HINSTANCE instance, TrafficAggregator& aggregator,
                      ProcessInfoCache& process_cache, EtwMonitor& monitor) {
    if (!RegisterWindowClass(instance)) {
        return nullptr;
    }

    constexpr DWORD style = WS_OVERLAPPEDWINDOW;
    constexpr DWORD extended_style = 0;
    const UINT dpi = SystemDpi();
    RECT window_rectangle{0, 0, ScaleForDpi(1050, dpi), ScaleForDpi(620, dpi)};
    AdjustWindowRectForDpi(window_rectangle, style, extended_style, dpi);

    auto* state = new MainWindow(aggregator, process_cache, monitor);
    MainWindow::CreationContext context{state};
    HWND window = CreateWindowExW(
        extended_style, kWindowClassName, L"NetAssess 进程流量监视器", style,
        CW_USEDEFAULT, CW_USEDEFAULT,
        window_rectangle.right - window_rectangle.left,
        window_rectangle.bottom - window_rectangle.top,
        nullptr, nullptr, instance, &context);
    if (window == nullptr && !context.attached) {
        delete state;
    }
    return window;
}

bool StartMainWindowCollection(HWND window) {
    return SendMessageW(window, kStartCollectionMessage, 0, 0) != FALSE;
}
