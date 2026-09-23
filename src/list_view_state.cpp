#include "list_view_state.h"

#include <commctrl.h>

void UpdateListViewSortIndicator(HWND list_view, int column, bool ascending) {
    if (list_view == nullptr || column < 0) {
        return;
    }

    HWND header = ListView_GetHeader(list_view);
    if (header == nullptr) {
        return;
    }

    const int column_count = Header_GetItemCount(header);
    if (column >= column_count) {
        return;
    }

    for (int index = 0; index < column_count; ++index) {
        HDITEMW item{};
        item.mask = HDI_FORMAT;
        if (!Header_GetItem(header, index, &item)) {
            continue;
        }

        item.fmt &= ~(HDF_SORTUP | HDF_SORTDOWN);
        if (index == column) {
            item.fmt |= ascending ? HDF_SORTUP : HDF_SORTDOWN;
        }
        Header_SetItem(header, index, &item);
    }
}

ListScrollState::ProgrammaticScrollGuard::ProgrammaticScrollGuard(
    ListScrollState& state) noexcept
    : state_(state) {
    ++state_.programmatic_scroll_depth_;
}

ListScrollState::ProgrammaticScrollGuard::~ProgrammaticScrollGuard() {
    --state_.programmatic_scroll_depth_;
}

void ListScrollState::ResetToAutoTop() noexcept {
    auto_top_ = true;
}

void ListScrollState::ObserveUserScroll(bool at_top) noexcept {
    if (programmatic_scroll_depth_ == 0) {
        auto_top_ = at_top;
    }
}

bool ListScrollState::auto_top() const noexcept {
    return auto_top_;
}

ListScrollState::ProgrammaticScrollGuard ListScrollState::GuardProgrammaticScroll() noexcept {
    return ProgrammaticScrollGuard(*this);
}
