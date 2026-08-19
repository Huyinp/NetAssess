#include "connection_window.h"

#include "connection_aggregator.h"
#include "connection_view.h"
#include "formatting.h"
#include "process_info.h"
#include "protocol_classifier.h"
#include "win32_dpi.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <map>
#include <optional>
#include <set>
#include <string_view>
#include <vector>

#include <commctrl.h>

namespace {

constexpr wchar_t kWindowClassName[] = L"NetAssessConnectionWindow";

ConnectionSortColumn SortColumnForListColumn(int column) {
    constexpr std::array columns{
        ConnectionSortColumn::Status,
        ConnectionSortColumn::Direction,
        ConnectionSortColumn::Transport,
        ConnectionSortColumn::ApplicationProtocol,
        ConnectionSortColumn::LocalAddress,
        ConnectionSortColumn::LocalPort,
        ConnectionSortColumn::RemoteAddress,
        ConnectionSortColumn::RemotePort,
        ConnectionSortColumn::SentBytes,
        ConnectionSortColumn::SentRate,
        ConnectionSortColumn::ReceivedBytes,
        ConnectionSortColumn::ReceivedRate,
    };
    return column >= 0 && column < static_cast<int>(columns.size())
               ? columns[static_cast<std::size_t>(column)]
               : ConnectionSortColumn::CombinedSpeed;
}

class ConnectionWindow {
public:
    ConnectionWindow(ProcessInstanceId process, ConnectionAggregator& aggregator,
                     ProcessInfoCache& process_cache)
        : process_(process),
          aggregator_(aggregator),
          process_cache_(process_cache) {}

    static LRESULT CALLBACK WindowProcedure(HWND window, UINT message, WPARAM wparam,
                                            LPARAM lparam) {
        auto* self = reinterpret_cast<ConnectionWindow*>(
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
        ConnectionWindow* window;
        bool attached{};
    };

private:
    LRESULT HandleMessage(UINT message, WPARAM wparam, LPARAM lparam) {
        switch (message) {
        case WM_CREATE:
            dpi_ = win32_dpi::Window(window_);
            if (!CreateControls()) {
                return -1;
            }
            aggregator_.ResetSnapshotBaseline(process_);
            return 0;
        case kConnectionWindowRefreshMessage:
            RefreshSnapshot();
            return 0;
        case WM_NOTIFY:
            HandleNotify(reinterpret_cast<NMHDR*>(lparam));
            return 0;
        case WM_SIZE:
            LayoutControls();
            return 0;
        case WM_GETMINMAXINFO: {
            auto* sizing = reinterpret_cast<MINMAXINFO*>(lparam);
            sizing->ptMinTrackSize.x = win32_dpi::Scale(820, dpi_);
            sizing->ptMinTrackSize.y = win32_dpi::Scale(400, dpi_);
            return 0;
        }
        case WM_DPICHANGED: {
            dpi_ = HIWORD(wparam);
            const auto* suggested = reinterpret_cast<RECT*>(lparam);
            SetWindowPos(window_, nullptr, suggested->left, suggested->top,
                         suggested->right - suggested->left,
                         suggested->bottom - suggested->top,
                         SWP_NOACTIVATE | SWP_NOZORDER);
            UpdateColumnWidths();
            LayoutControls();
            return 0;
        }
        case WM_CLOSE:
            DestroyWindow(window_);
            return 0;
        default:
            return DefWindowProcW(window_, message, wparam, lparam);
        }
    }

    bool CreateControls() {
        list_view_ = CreateWindowExW(
            WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS,
            0, 0, 0, 0, window_, nullptr,
            reinterpret_cast<HINSTANCE>(GetWindowLongPtrW(window_, GWLP_HINSTANCE)), nullptr);
        if (list_view_ == nullptr) {
            return false;
        }

        SendMessageW(list_view_, WM_SETFONT,
                     reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)), TRUE);
        ListView_SetExtendedListViewStyleEx(
            list_view_, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);

        constexpr std::array<std::wstring_view, 12> column_names{
            L"状态",       L"方向",       L"传输层协议", L"推断应用协议",
            L"本地地址",   L"本地端口",   L"远端地址",   L"远端端口",
            L"上行累计",   L"上行速度",   L"下行累计",   L"下行速度",
        };
        for (int index = 0; index < static_cast<int>(column_names.size()); ++index) {
            LVCOLUMNW column{};
            column.mask = LVCF_TEXT | LVCF_SUBITEM;
            column.pszText = const_cast<wchar_t*>(
                column_names[static_cast<std::size_t>(index)].data());
            column.iSubItem = index;
            if (ListView_InsertColumn(list_view_, index, &column) == -1) {
                return false;
            }
        }
        UpdateColumnWidths();
        LayoutControls();
        return true;
    }

    void UpdateColumnWidths() const {
        constexpr std::array<int, 12> column_widths{
            88, 70, 92, 170, 190, 82, 190, 82, 105, 105, 105, 105,
        };
        for (int index = 0; index < static_cast<int>(column_widths.size()); ++index) {
            ListView_SetColumnWidth(
                list_view_, index,
                win32_dpi::Scale(column_widths[static_cast<std::size_t>(index)], dpi_));
        }
    }

    void LayoutControls() const {
        if (list_view_ == nullptr) {
            return;
        }
        RECT client{};
        GetClientRect(window_, &client);
        const int margin = win32_dpi::Scale(8, dpi_);
        MoveWindow(list_view_, margin, margin,
                   std::max(0, static_cast<int>(client.right) - margin * 2),
                   std::max(0, static_cast<int>(client.bottom) - margin * 2), TRUE);
    }

    void HandleNotify(const NMHDR* notification) {
        if (notification == nullptr || notification->hwndFrom != list_view_ ||
            notification->code != LVN_COLUMNCLICK) {
            return;
        }
        const auto* column_click = reinterpret_cast<const NMLISTVIEW*>(notification);
        const ConnectionSortColumn clicked_column =
            SortColumnForListColumn(column_click->iSubItem);
        if (sort_column_ == clicked_column) {
            ascending_ = !ascending_;
        } else {
            sort_column_ = clicked_column;
            ascending_ = true;
        }
        SortConnectionRows(rows_, sort_column_, ascending_);
        ReconcileRows();
    }

    void RefreshSnapshot() {
        const auto now = std::chrono::steady_clock::now();
        const auto snapshots = aggregator_.Snapshot(process_, now);
        rows_ = BuildConnectionRows(snapshots, process_cache_.RefreshAlive(process_),
                                    now, sort_column_, ascending_);
        ReconcileRows();
    }

    void ReconcileRows() {
        const std::set<ConnectionKey> selected_keys = SelectedKeys();
        const ScrollAnchor scroll_anchor = CaptureScrollAnchor();
        ReconcileRowStructure();
        for (int index = 0; index < static_cast<int>(rows_.size()); ++index) {
            UpdateRow(index, rows_[static_cast<std::size_t>(index)]);
        }
        RestoreSelection(selected_keys);
        RestoreScrollAnchor(scroll_anchor);
    }

    std::set<ConnectionKey> SelectedKeys() const {
        std::set<ConnectionKey> selected;
        for (int index = 0; index < static_cast<int>(current_keys_.size()); ++index) {
            if ((ListView_GetItemState(list_view_, index, LVIS_SELECTED) & LVIS_SELECTED) != 0) {
                selected.insert(current_keys_[static_cast<std::size_t>(index)]);
            }
        }
        return selected;
    }

    struct ScrollAnchor {
        std::optional<ConnectionKey> key;
        int previous_top{};
    };

    ScrollAnchor CaptureScrollAnchor() const {
        const int top = ListView_GetTopIndex(list_view_);
        if (top >= 0 && top < static_cast<int>(current_keys_.size())) {
            return {current_keys_[static_cast<std::size_t>(top)], top};
        }
        return {std::nullopt, top};
    }

    void ReconcileRowStructure() {
        std::set<ConnectionKey> desired_keys;
        for (const ConnectionDisplayRow& row : rows_) {
            desired_keys.insert(row.connection.key);
        }

        for (int index = static_cast<int>(current_keys_.size()) - 1; index >= 0; --index) {
            if (!desired_keys.contains(current_keys_[static_cast<std::size_t>(index)])) {
                if (ListView_DeleteItem(list_view_, index)) {
                    current_keys_.erase(current_keys_.begin() + index);
                }
            }
        }
        RebuildRowMap();

        for (int target = 0; target < static_cast<int>(rows_.size()); ++target) {
            const ConnectionKey& key = rows_[static_cast<std::size_t>(target)].connection.key;
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

    void UpdateRow(int index, const ConnectionDisplayRow& row) const {
        const ConnectionSnapshot& connection = row.connection;
        SetItemText(index, 0, ConnectionActivityStatusText(row.status));
        SetItemText(index, 1, ConnectionDirectionName(row.direction));
        SetItemText(index, 2, TransportProtocolName(connection.key.transport));
        SetItemText(index, 3, ApplicationProtocolName(connection.key.application_protocol));
        SetItemText(index, 4, FormatIpAddress(connection.key.local.address));
        SetItemText(index, 5, std::to_wstring(connection.key.local.port));
        SetItemText(index, 6, FormatIpAddress(connection.key.remote.address));
        SetItemText(index, 7, std::to_wstring(connection.key.remote.port));
        SetItemText(index, 8, FormatBytes(connection.sent_bytes));
        SetItemText(index, 9, FormatRate(connection.sent_bytes_per_second));
        SetItemText(index, 10, FormatBytes(connection.received_bytes));
        SetItemText(index, 11, FormatRate(connection.received_bytes_per_second));
    }

    void SetItemText(int row, int column, std::wstring_view text) const {
        std::wstring value{text};
        LVITEMW item{};
        item.iSubItem = column;
        item.pszText = value.data();
        SendMessageW(list_view_, LVM_SETITEMTEXTW, row,
                     reinterpret_cast<LPARAM>(&item));
    }

    void RestoreSelection(const std::set<ConnectionKey>& selected_keys) const {
        ListView_SetItemState(list_view_, -1, 0, LVIS_SELECTED);
        for (const ConnectionKey& key : selected_keys) {
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

    ProcessInstanceId process_;
    ConnectionAggregator& aggregator_;
    ProcessInfoCache& process_cache_;
    HWND window_{};
    HWND list_view_{};
    UINT dpi_{win32_dpi::kDefaultDpi};
    ConnectionSortColumn sort_column_{ConnectionSortColumn::CombinedSpeed};
    bool ascending_{};
    std::vector<ConnectionDisplayRow> rows_;
    std::vector<ConnectionKey> current_keys_;
    std::map<ConnectionKey, int> row_map_;
};

bool RegisterWindowClass(HINSTANCE instance) {
    WNDCLASSEXW window_class{};
    window_class.cbSize = sizeof(window_class);
    window_class.style = CS_HREDRAW | CS_VREDRAW;
    window_class.lpfnWndProc = ConnectionWindow::WindowProcedure;
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

HWND CreateConnectionWindow(HINSTANCE instance, HWND owner, ProcessInstanceId process,
                            std::wstring process_name, ConnectionAggregator& aggregator,
                            ProcessInfoCache& process_cache) {
    if (!RegisterWindowClass(instance)) {
        return nullptr;
    }

    constexpr DWORD style = WS_OVERLAPPEDWINDOW;
    constexpr DWORD extended_style = 0;
    const UINT dpi = win32_dpi::System();
    RECT window_rectangle{0, 0, win32_dpi::Scale(1180, dpi), win32_dpi::Scale(600, dpi)};
    win32_dpi::AdjustWindowRect(window_rectangle, style, extended_style, dpi);

    std::wstring title = process_name + L"（PID " + std::to_wstring(process.pid) +
                         L"）连接明细";
    auto* state = new ConnectionWindow(process, aggregator, process_cache);
    ConnectionWindow::CreationContext context{state};
    HWND window = CreateWindowExW(
        extended_style, kWindowClassName, title.c_str(), style,
        CW_USEDEFAULT, CW_USEDEFAULT,
        window_rectangle.right - window_rectangle.left,
        window_rectangle.bottom - window_rectangle.top,
        owner, nullptr, instance, &context);
    if (window == nullptr && !context.attached) {
        delete state;
    }
    return window;
}
