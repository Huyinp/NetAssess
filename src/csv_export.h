#pragma once

#include <span>
#include <string>
#include <string_view>
#include <vector>

#define NOMINMAX
#include <windows.h>

struct CsvBuildResult {
    std::string bytes;
    DWORD error;
};

CsvBuildResult BuildCsvUtf8(std::span<const std::wstring> headers,
                            std::span<const std::vector<std::wstring>> rows);

DWORD WriteCsvFile(std::wstring_view path, std::string_view bytes);

struct CsvSaveResult {
    bool saved;
    DWORD error;
};

CsvSaveResult SaveCsvWithDialog(HWND owner, std::wstring_view default_name,
                                std::span<const std::wstring> headers,
                                std::span<const std::vector<std::wstring>> rows);
