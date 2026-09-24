#include "connection_window.h"

#include "connection_aggregator.h"
#include "connection_view.h"
#include "csv_export.h"
#include "list_view_state.h"
#include "process_info.h"
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
constexpr int kPortFilterId = 101;
constexpr int kIpFilterId = 102;
constexpr int kExportId = 103;
constexpr std::array<std::wstring_view, 12> kColumnNames{
    L"状态", L"方向", L"传输层协议", L"推断应用协议",
    L"本地地址", L"本地端口", L"远端地址", L"远端端口",
    L"上行累计", L"上行速度", L"下行累计", L"下行速度",
};

void DefaultErrorPresenter(HWND owner, std::wstring_view operation, DWORD error) {
    const std::wstring message = std::wstring(operation) + L"（错误代码 " +
                                 std::to_wstring(error) + L"）";
    MessageBoxW(owner, message.c_str(), L"连接明细", MB_OK | MB_ICONERROR);
}

DWORD CreationError() {
    const DWORD error = GetLastError();
    return error == ERROR_SUCCESS ? ERROR_GEN_FAILURE : error;
}

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
    ConnectionWindow(HWND owner, ProcessInstanceId process,
                     ConnectionAggregator& aggregator,
                     ProcessInfoCache& process_cache,
                     ConnectionErrorPresenter error_presenter)
        : owner_(owner),
          process_(process),
          aggregator_(aggregator),
          process_cache_(process_cache),
          error_presenter_(error_presenter != nullptr ? error_presenter : DefaultErrorPresenter) {}

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

        if (message == WM_NCDESTROY && self != nullptr && self->owner_ != nullptr) {
            SendMessageW(self->owner_, kConnectionWindowClosedMessage,
                         reinterpret_cast<WPARAM>(window), 0);
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
        DWORD error{};
    };

private:
    struct ListPane {
        TransportProtocol transport{};
        HWND list{};
        ListScrollState scroll_state;
        ConnectionSortColumn sort_column{ConnectionSortColumn::CombinedSpeed};
        bool ascending{};
        std::vector<ConnectionDisplayRow> rows;
        std::vector<ConnectionKey> current_keys;
        std::map<ConnectionKey, int> row_map;
    };

    LRESULT HandleMessage(UINT message, WPARAM wparam, LPARAM lparam) {
        switch (message) {
        case WM_CREATE: {
            dpi_ = win32_dpi::Window(window_);
            SetLastError(ERROR_SUCCESS);
            if (!CreateControls()) {
                auto* create = reinterpret_cast<CREATESTRUCTW*>(lparam);
                static_cast<CreationContext*>(create->lpCreateParams)->error =
                    creation_error_ != ERROR_SUCCESS ? creation_error_ : CreationError();
                return -1;
            }
            aggregator_.ResetSnapshotBaseline(process_);
            return 0;
        }
        case kConnectionWindowRefreshMessage:
            RefreshSnapshot();
            return 0;
        case WM_NOTIFY:
            if (const auto* notification = reinterpret_cast<NMHDR*>(lparam);
                notification != nullptr && notification->hwndFrom == tab_control_ &&
                notification->code == TCN_SELCHANGE) {
                const int selected = TabCtrl_GetCurSel(tab_control_);
                if (selected >= 0) { SwitchPane(static_cast<std::size_t>(selected)); }
            } else {
                HandleNotify(notification);
            }
            return 0;
        case WM_COMMAND:
            if (reinterpret_cast<HWND>(lparam) == ip_edit_ && HIWORD(wparam) == EN_CHANGE) {
                ApplyFilterChange(false);
            } else if (reinterpret_cast<HWND>(lparam) == port_edit_ &&
                       HIWORD(wparam) == EN_CHANGE) {
                ApplyFilterChange(true);
            } else if (reinterpret_cast<HWND>(lparam) == export_button_ &&
                       HIWORD(wparam) == BN_CLICKED) {
                ExportRows();
            }
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
        const HINSTANCE instance = reinterpret_cast<HINSTANCE>(
            GetWindowLongPtrW(window_, GWLP_HINSTANCE));
        auto create_control = [&](const wchar_t* class_name, const wchar_t* text,
                                  DWORD style, int id) {
            return CreateWindowExW(0, class_name, text, WS_CHILD | WS_VISIBLE | style,
                                   0, 0, 0, 0, window_, reinterpret_cast<HMENU>(
                                       static_cast<INT_PTR>(id)), instance, nullptr);
        };
        ip_label_ = create_control(L"STATIC", L"IP", SS_LEFT, 0);
        if (ip_label_ == nullptr) { return false; }
        port_label_ = create_control(L"STATIC", L"端口", SS_LEFT, 0);
        if (port_label_ == nullptr) { return false; }
        port_edit_ = create_control(L"EDIT", L"", WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
                                    kPortFilterId);
        if (port_edit_ == nullptr) { return false; }
        ip_edit_ = create_control(L"EDIT", L"", WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
                                  kIpFilterId);
        if (ip_edit_ == nullptr) { return false; }
        export_button_ = create_control(L"BUTTON", L"导出 CSV", WS_TABSTOP | BS_PUSHBUTTON,
                                        kExportId);
        if (export_button_ == nullptr) { return false; }
        tab_control_ = create_control(WC_TABCONTROLW, L"", WS_TABSTOP, 0);
        if (tab_control_ == nullptr) { return false; }
        panes_[0].transport = TransportProtocol::Tcp;
        panes_[1].transport = TransportProtocol::Udp;
        constexpr std::array<std::wstring_view, 2> tab_names{L"TCP 列表", L"UDP 列表"};
        for (int index = 0; index < static_cast<int>(tab_names.size()); ++index) {
            TCITEMW item{};
            item.mask = TCIF_TEXT;
            item.pszText = const_cast<wchar_t*>(tab_names[static_cast<std::size_t>(index)].data());
            if (TabCtrl_InsertItem(tab_control_, index, &item) == -1) { return false; }
        }
        for (std::size_t pane_index = 0; pane_index < panes_.size(); ++pane_index) {
            ListPane& pane = panes_[pane_index];
            pane.list = CreateWindowExW(
                WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                WS_CHILD | LVS_REPORT | LVS_SHOWSELALWAYS,
                0, 0, 0, 0, window_, nullptr, instance, nullptr);
            if (pane.list == nullptr) { return false; }
            SendMessageW(pane.list, WM_SETFONT,
                         reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)), TRUE);
            ListView_SetExtendedListViewStyleEx(
                pane.list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER,
                LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
            for (int column_index = 0;
                 column_index < static_cast<int>(kColumnNames.size()); ++column_index) {
                LVCOLUMNW column{};
                column.mask = LVCF_TEXT | LVCF_SUBITEM;
                column.pszText = const_cast<wchar_t*>(
                    kColumnNames[static_cast<std::size_t>(column_index)].data());
                column.iSubItem = column_index;
                if (ListView_InsertColumn(pane.list, column_index, &column) == -1) {
                    return false;
                }
            }
            SetLastError(ERROR_SUCCESS);
            if (!SetWindowSubclass(pane.list, ListProcedure,
                                   static_cast<UINT_PTR>(pane_index + 1),
                                   reinterpret_cast<DWORD_PTR>(this))) {
                creation_error_ = CreationError();
                return false;
            }
        }
        for (HWND control : {ip_label_, port_label_, port_edit_, ip_edit_, export_button_}) {
            SendMessageW(control, WM_SETFONT,
                         reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)), TRUE);
        }
        SendMessageW(tab_control_, WM_SETFONT,
                     reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)), TRUE);
        SwitchPane(0);
        UpdateColumnWidths();
        LayoutControls();
        return true;
    }

    void UpdateColumnWidths() const {
        constexpr std::array<int, 12> column_widths{
            88, 70, 92, 170, 190, 82, 190, 82, 105, 105, 105, 105,
        };
        for (const ListPane& pane : panes_) {
            for (int index = 0; index < static_cast<int>(column_widths.size()); ++index) {
                ListView_SetColumnWidth(
                    pane.list, index,
                    win32_dpi::Scale(column_widths[static_cast<std::size_t>(index)], dpi_));
            }
        }
    }

    void LayoutControls() const {
        if (tab_control_ == nullptr || export_button_ == nullptr) {
            return;
        }
        RECT client{};
        GetClientRect(window_, &client);
        const int margin = win32_dpi::Scale(8, dpi_);
        const int control_height = win32_dpi::Scale(25, dpi_);
        const int gap = win32_dpi::Scale(7, dpi_);
        int x = margin;
        const auto place = [&](HWND control, int width) {
            const int scaled_width = win32_dpi::Scale(width, dpi_);
            MoveWindow(control, x, margin, scaled_width, control_height, TRUE);
            x += scaled_width + gap;
        };
        place(ip_label_, 20);
        place(ip_edit_, 200);
        place(port_label_, 36);
        place(port_edit_, 90);
        place(export_button_, 100);
        const int list_top = margin + control_height + margin;
        MoveWindow(tab_control_, margin, list_top,
                   std::max(0, static_cast<int>(client.right) - margin * 2),
                   std::max(0, static_cast<int>(client.bottom) - list_top - margin), TRUE);
        RECT page{};
        GetClientRect(tab_control_, &page);
        TabCtrl_AdjustRect(tab_control_, FALSE, &page);
        MapWindowPoints(tab_control_, window_, reinterpret_cast<POINT*>(&page), 2);
        for (const ListPane& pane : panes_) {
            MoveWindow(pane.list, page.left, page.top,
                       std::max(0, static_cast<int>(page.right - page.left)),
                       std::max(0, static_cast<int>(page.bottom - page.top)), TRUE);
        }
    }

    void SwitchPane(std::size_t index) {
        if (index >= panes_.size()) { return; }
        active_pane_ = index;
        TabCtrl_SetCurSel(tab_control_, static_cast<int>(index));
        for (std::size_t pane_index = 0; pane_index < panes_.size(); ++pane_index) {
            ShowWindow(panes_[pane_index].list,
                       pane_index == active_pane_ ? SW_SHOW : SW_HIDE);
        }
    }

    static LRESULT CALLBACK ListProcedure(HWND list, UINT message, WPARAM wparam,
                                          LPARAM lparam, UINT_PTR subclass_id,
                                          DWORD_PTR context) {
        auto* self = reinterpret_cast<ConnectionWindow*>(context);
        if (message == WM_NCDESTROY) {
            RemoveWindowSubclass(list, ListProcedure, subclass_id);
            return DefSubclassProc(list, message, wparam, lparam);
        }
        const bool user_scroll = message == WM_VSCROLL || message == WM_MOUSEWHEEL ||
            (message == WM_KEYDOWN &&
             (wparam == VK_UP || wparam == VK_DOWN || wparam == VK_PRIOR ||
              wparam == VK_NEXT || wparam == VK_HOME || wparam == VK_END));
        const LRESULT result = DefSubclassProc(list, message, wparam, lparam);
        if (user_scroll) {
            if (ListPane* pane = self->PaneForList(list)) {
                pane->scroll_state.ObserveUserScroll(ListView_GetTopIndex(list) == 0);
            }
        }
        return result;
    }

    ListPane* PaneForList(HWND list) {
        for (ListPane& pane : panes_) {
            if (pane.list == list) { return &pane; }
        }
        return nullptr;
    }

    static std::wstring EditText(HWND edit) {
        std::wstring text(static_cast<std::size_t>(GetWindowTextLengthW(edit)) + 1, L'\0');
        text.resize(static_cast<std::size_t>(GetWindowTextW(
            edit, text.data(), static_cast<int>(text.size()))));
        return text;
    }

    void ApplyFilterChange(bool port_changed) {
        if (port_changed) {
            std::wstring port = EditText(port_edit_);
            const std::size_t first = port.find_first_not_of(L" \t\r\n");
            port = first == std::wstring::npos
                ? std::wstring{}
                : port.substr(first, port.find_last_not_of(L" \t\r\n") - first + 1);
            const PortFilterParseResult parsed = ParsePortFilter(port);
            if (!parsed.valid) {
                if (!invalid_port_reported_) {
                    invalid_port_reported_ = true;
                    error_presenter_(window_, L"端口筛选无效，请输入 0–65535 的十进制端口",
                                     ERROR_INVALID_DATA);
                }
                return;
            }
            invalid_port_reported_ = false;
            filter_.port = std::move(port);
        } else {
            filter_.ip = EditText(ip_edit_);
        }
        for (ListPane& pane : panes_) { pane.scroll_state.ResetToAutoTop(); }
        RebuildFilteredRows();
    }

    void RebuildFilteredRows() {
        const auto filtered = FilterConnectionRows(raw_rows_, filter_);
        for (ListPane& pane : panes_) { pane.rows.clear(); }
        for (const ConnectionDisplayRow& row : filtered) {
            for (ListPane& pane : panes_) {
                if (row.connection.key.transport == pane.transport) {
                    pane.rows.push_back(row);
                    break;
                }
            }
        }
        for (ListPane& pane : panes_) {
            SortConnectionRows(pane.rows, pane.sort_column, pane.ascending);
            ReconcileRows(pane);
        }
    }

    void ExportRows() {
        std::array<std::wstring, 12> headers{};
        for (std::size_t index = 0; index < headers.size(); ++index) {
            headers[index] = kColumnNames[index];
        }
        std::vector<std::vector<std::wstring>> data;
        const ListPane& pane = panes_[active_pane_];
        data.reserve(pane.rows.size());
        for (const ConnectionDisplayRow& row : pane.rows) {
            data.push_back(ConnectionCsvCells(row));
        }
        const CsvSaveResult result = SaveCsvWithDialog(window_, L"连接明细.csv", headers, data);
        if (result.error != ERROR_SUCCESS) {
            error_presenter_(window_, L"导出 CSV 失败", result.error);
        }
    }

    void HandleNotify(const NMHDR* notification) {
        if (notification == nullptr || notification->code != LVN_COLUMNCLICK) {
            return;
        }
        ListPane* pane = PaneForList(notification->hwndFrom);
        if (pane == nullptr) { return; }
        const auto* column_click = reinterpret_cast<const NMLISTVIEW*>(notification);
        const ConnectionSortColumn clicked_column =
            SortColumnForListColumn(column_click->iSubItem);
        if (pane->sort_column == clicked_column) {
            pane->ascending = !pane->ascending;
        } else {
            pane->sort_column = clicked_column;
            pane->ascending = true;
        }
        pane->scroll_state.ResetToAutoTop();
        UpdateListViewSortIndicator(pane->list, column_click->iSubItem, pane->ascending);
        SortConnectionRows(pane->rows, pane->sort_column, pane->ascending);
        ReconcileRows(*pane);
    }

    void RefreshSnapshot() {
        const auto now = std::chrono::steady_clock::now();
        const auto snapshots = aggregator_.Snapshot(process_, now);
        raw_rows_ = BuildConnectionRows(snapshots, process_cache_.RefreshAlive(process_), now);
        RebuildFilteredRows();
    }

    void ReconcileRows(ListPane& pane) {
        auto guard = pane.scroll_state.GuardProgrammaticScroll();
        const std::set<ConnectionKey> selected_keys = SelectedKeys(pane);
        const ScrollAnchor scroll_anchor = CaptureScrollAnchor(pane);
        ReconcileRowStructure(pane);
        for (int index = 0; index < static_cast<int>(pane.rows.size()); ++index) {
            UpdateRow(pane, index, pane.rows[static_cast<std::size_t>(index)]);
        }
        RestoreSelection(pane, selected_keys);
        RestoreScrollAnchor(pane, scroll_anchor);
    }

    std::set<ConnectionKey> SelectedKeys(const ListPane& pane) const {
        std::set<ConnectionKey> selected;
        for (int index = 0; index < static_cast<int>(pane.current_keys.size()); ++index) {
            if ((ListView_GetItemState(pane.list, index, LVIS_SELECTED) & LVIS_SELECTED) != 0) {
                selected.insert(pane.current_keys[static_cast<std::size_t>(index)]);
            }
        }
        return selected;
    }

    struct ScrollAnchor {
        std::optional<ConnectionKey> key;
        int previous_top{};
    };

    ScrollAnchor CaptureScrollAnchor(const ListPane& pane) const {
        const int top = ListView_GetTopIndex(pane.list);
        if (top >= 0 && top < static_cast<int>(pane.current_keys.size())) {
            return {pane.current_keys[static_cast<std::size_t>(top)], top};
        }
        return {std::nullopt, top};
    }

    void ReconcileRowStructure(ListPane& pane) {
        std::set<ConnectionKey> desired_keys;
        for (const ConnectionDisplayRow& row : pane.rows) {
            desired_keys.insert(row.connection.key);
        }

        for (int index = static_cast<int>(pane.current_keys.size()) - 1; index >= 0; --index) {
            if (!desired_keys.contains(pane.current_keys[static_cast<std::size_t>(index)])) {
                if (ListView_DeleteItem(pane.list, index)) {
                    pane.current_keys.erase(pane.current_keys.begin() + index);
                }
            }
        }
        RebuildRowMap(pane);

        for (int target = 0; target < static_cast<int>(pane.rows.size()); ++target) {
            const ConnectionKey& key = pane.rows[static_cast<std::size_t>(target)].connection.key;
            const auto existing = pane.row_map.find(key);
            if (existing == pane.row_map.end()) {
                if (InsertBlankRow(pane, target)) {
                    pane.current_keys.insert(pane.current_keys.begin() + target, key);
                    RebuildRowMap(pane);
                }
            } else if (existing->second != target) {
                const int source = existing->second;
                if (ListView_DeleteItem(pane.list, source)) {
                    pane.current_keys.erase(pane.current_keys.begin() + source);
                    if (InsertBlankRow(pane, target)) {
                        pane.current_keys.insert(pane.current_keys.begin() + target, key);
                    }
                    RebuildRowMap(pane);
                }
            }
        }
    }

    bool InsertBlankRow(const ListPane& pane, int index) const {
        wchar_t blank[] = L"";
        LVITEMW item{};
        item.mask = LVIF_TEXT;
        item.iItem = index;
        item.pszText = blank;
        return ListView_InsertItem(pane.list, &item) != -1;
    }

    void RebuildRowMap(ListPane& pane) {
        pane.row_map.clear();
        for (int index = 0; index < static_cast<int>(pane.current_keys.size()); ++index) {
            pane.row_map.emplace(pane.current_keys[static_cast<std::size_t>(index)], index);
        }
    }

    void UpdateRow(const ListPane& pane, int index, const ConnectionDisplayRow& row) const {
        const auto cells = ConnectionCsvCells(row);
        for (int column = 0; column < static_cast<int>(cells.size()); ++column) {
            SetItemText(pane, index, column, cells[static_cast<std::size_t>(column)]);
        }
    }

    void SetItemText(const ListPane& pane, int row, int column, std::wstring_view text) const {
        std::wstring value{text};
        LVITEMW item{};
        item.iSubItem = column;
        item.pszText = value.data();
        SendMessageW(pane.list, LVM_SETITEMTEXTW, row,
                     reinterpret_cast<LPARAM>(&item));
    }

    void RestoreSelection(const ListPane& pane,
                          const std::set<ConnectionKey>& selected_keys) const {
        ListView_SetItemState(pane.list, -1, 0, LVIS_SELECTED);
        for (const ConnectionKey& key : selected_keys) {
            const auto row = pane.row_map.find(key);
            if (row != pane.row_map.end()) {
                ListView_SetItemState(pane.list, row->second, LVIS_SELECTED, LVIS_SELECTED);
            }
        }
    }

    void RestoreScrollAnchor(const ListPane& pane, const ScrollAnchor& anchor) const {
        const int count = ListView_GetItemCount(pane.list);
        if (count == 0) {
            return;
        }
        int target = pane.scroll_state.auto_top() ? 0 :
            std::clamp(anchor.previous_top, 0, count - 1);
        if (!pane.scroll_state.auto_top() && anchor.key) {
            const auto row = pane.row_map.find(*anchor.key);
            if (row != pane.row_map.end()) {
                target = row->second;
            }
        }
        ListView_EnsureVisible(pane.list, target, FALSE);
        RECT item_rectangle{};
        if (ListView_GetItemRect(pane.list, 0, &item_rectangle, LVIR_BOUNDS)) {
            const int current_top = ListView_GetTopIndex(pane.list);
            ListView_Scroll(pane.list, 0,
                            (target - current_top) *
                                (item_rectangle.bottom - item_rectangle.top));
        }
    }

    HWND owner_{};
    ProcessInstanceId process_;
    ConnectionAggregator& aggregator_;
    ProcessInfoCache& process_cache_;
    HWND window_{};
    HWND tab_control_{};
    HWND ip_label_{};
    HWND ip_edit_{};
    HWND port_label_{};
    HWND port_edit_{};
    HWND export_button_{};
    ConnectionErrorPresenter error_presenter_{};
    ConnectionFilter filter_;
    bool invalid_port_reported_{};
    DWORD creation_error_{};
    UINT dpi_{win32_dpi::kDefaultDpi};
    std::array<ListPane, 2> panes_{};
    std::size_t active_pane_{};
    std::vector<ConnectionDisplayRow> raw_rows_;
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

ConnectionWindowCreationResult CreateConnectionWindow(
    HINSTANCE instance, HWND owner, ProcessInstanceId process, std::wstring process_name,
    ConnectionAggregator& aggregator, ProcessInfoCache& process_cache,
    ConnectionErrorPresenter error_presenter) {
    if (!RegisterWindowClass(instance)) {
        return {nullptr, CreationError()};
    }

    constexpr DWORD style = WS_OVERLAPPEDWINDOW;
    constexpr DWORD extended_style = 0;
    const UINT dpi = win32_dpi::System();
    RECT window_rectangle{0, 0, win32_dpi::Scale(1450, dpi), win32_dpi::Scale(600, dpi)};
    win32_dpi::AdjustWindowRect(window_rectangle, style, extended_style, dpi);

    std::wstring title = process_name + L" — PID " + std::to_wstring(process.pid) +
                         L" — 连接明细";
    auto* state = new ConnectionWindow(owner, process, aggregator, process_cache,
                                       error_presenter);
    ConnectionWindow::CreationContext context{state};
    SetLastError(ERROR_SUCCESS);
    HWND window = CreateWindowExW(
        extended_style, kWindowClassName, title.c_str(), style,
        CW_USEDEFAULT, CW_USEDEFAULT,
        window_rectangle.right - window_rectangle.left,
        window_rectangle.bottom - window_rectangle.top,
        owner, nullptr, instance, &context);
    const DWORD error = window != nullptr ? ERROR_SUCCESS :
        context.error != ERROR_SUCCESS ? context.error : CreationError();
    if (window == nullptr && !context.attached) {
        delete state;
    }
    return {window, error};
}
