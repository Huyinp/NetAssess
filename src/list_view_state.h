#pragma once

#include <windows.h>

void UpdateListViewSortIndicator(HWND list_view, int column, bool ascending);

class ListScrollState {
public:
    class ProgrammaticScrollGuard {
    public:
        explicit ProgrammaticScrollGuard(ListScrollState& state) noexcept;
        ~ProgrammaticScrollGuard();

        ProgrammaticScrollGuard(const ProgrammaticScrollGuard&) = delete;
        ProgrammaticScrollGuard& operator=(const ProgrammaticScrollGuard&) = delete;

    private:
        ListScrollState& state_;
    };

    void ResetToAutoTop() noexcept;
    void ObserveUserScroll(bool at_top) noexcept;
    [[nodiscard]] bool auto_top() const noexcept;
    [[nodiscard]] ProgrammaticScrollGuard GuardProgrammaticScroll() noexcept;

private:
    bool auto_top_{true};
    unsigned int programmatic_scroll_depth_{};
};
