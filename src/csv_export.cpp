#include "csv_export.h"

#include <algorithm>
#include <array>
#include <limits>

#include <commdlg.h>

namespace {

DWORD ErrorOrGeneralFailure() {
    const DWORD error = GetLastError();
    return error == ERROR_SUCCESS ? ERROR_GEN_FAILURE : error;
}

DWORD AppendUtf8(std::wstring_view value, std::string& output) {
    if (value.empty()) {
        return ERROR_SUCCESS;
    }
    if (value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return ERROR_INVALID_PARAMETER;
    }

    const int wide_length = static_cast<int>(value.size());
    const int byte_length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                                                wide_length, nullptr, 0, nullptr, nullptr);
    if (byte_length == 0) {
        return ErrorOrGeneralFailure();
    }

    const std::size_t offset = output.size();
    output.resize(offset + static_cast<std::size_t>(byte_length));
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), wide_length,
                            output.data() + offset, byte_length, nullptr, nullptr) == 0) {
        return ErrorOrGeneralFailure();
    }
    return ERROR_SUCCESS;
}

DWORD AppendField(std::wstring_view field, std::string& output) {
    const bool needs_quotes = field.find_first_of(L",\"\r\n") != std::wstring_view::npos;
    if (needs_quotes) {
        output.push_back('\"');
    }
    std::size_t segment_start{};
    while (segment_start < field.size()) {
        const std::size_t quote = field.find(L'\"', segment_start);
        const std::size_t segment_end = quote == std::wstring_view::npos ? field.size() : quote;
        const DWORD error = AppendUtf8(field.substr(segment_start, segment_end - segment_start), output);
        if (error != ERROR_SUCCESS) {
            return error;
        }
        if (quote == std::wstring_view::npos) {
            break;
        }
        output.append("\"\"");
        segment_start = quote + 1;
    }
    if (needs_quotes) {
        output.push_back('\"');
    }
    return ERROR_SUCCESS;
}

DWORD AppendRow(std::span<const std::wstring> row, std::string& output) {
    for (std::size_t index = 0; index < row.size(); ++index) {
        if (index != 0) {
            output.push_back(',');
        }
        const DWORD error = AppendField(row[index], output);
        if (error != ERROR_SUCCESS) {
            return error;
        }
    }
    output.append("\r\n");
    return ERROR_SUCCESS;
}

}  // namespace

CsvBuildResult BuildCsvUtf8(std::span<const std::wstring> headers,
                            std::span<const std::vector<std::wstring>> rows) {
    for (const auto& row : rows) {
        if (row.size() != headers.size()) {
            return {{}, ERROR_INVALID_DATA};
        }
    }

    CsvBuildResult result{"\xEF\xBB\xBF", ERROR_SUCCESS};
    if (!headers.empty()) {
        result.error = AppendRow(headers, result.bytes);
        if (result.error != ERROR_SUCCESS) {
            result.bytes.clear();
            return result;
        }
    }
    for (const auto& row : rows) {
        result.error = AppendRow(row, result.bytes);
        if (result.error != ERROR_SUCCESS) {
            result.bytes.clear();
            return result;
        }
    }
    return result;
}

DWORD WriteCsvFile(std::wstring_view path, std::string_view bytes) {
    const std::wstring file_path(path);
    HANDLE file = CreateFileW(file_path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return ErrorOrGeneralFailure();
    }

    DWORD error = ERROR_SUCCESS;
    std::size_t offset{};
    while (offset < bytes.size()) {
        const std::size_t remaining = bytes.size() - offset;
        const DWORD chunk = static_cast<DWORD>(std::min(
            remaining, static_cast<std::size_t>(std::numeric_limits<DWORD>::max())));
        DWORD written{};
        if (!WriteFile(file, bytes.data() + offset, chunk, &written, nullptr)) {
            error = ErrorOrGeneralFailure();
            break;
        }
        if (written == 0) {
            error = ERROR_GEN_FAILURE;
            break;
        }
        offset += written;
    }
    if (error == ERROR_SUCCESS && !FlushFileBuffers(file)) {
        error = ErrorOrGeneralFailure();
    }
    if (!CloseHandle(file) && error == ERROR_SUCCESS) {
        error = ErrorOrGeneralFailure();
    }
    return error;
}

CsvSaveResult SaveCsvWithDialog(HWND owner, std::wstring_view default_name,
                                std::span<const std::wstring> headers,
                                std::span<const std::vector<std::wstring>> rows) {
    std::array<wchar_t, 32768> path{};
    if (default_name.size() >= path.size()) {
        return {false, ERROR_FILENAME_EXCED_RANGE};
    }
    std::copy(default_name.begin(), default_name.end(), path.begin());

    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = owner;
    dialog.lpstrFilter = L"CSV files (*.csv)\0*.csv\0\0";
    dialog.lpstrFile = path.data();
    dialog.nMaxFile = static_cast<DWORD>(path.size());
    dialog.lpstrDefExt = L"csv";
    dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (!GetSaveFileNameW(&dialog)) {
        const DWORD error = CommDlgExtendedError();
        return {false, error};
    }

    CsvBuildResult build = BuildCsvUtf8(headers, rows);
    if (build.error != ERROR_SUCCESS) {
        return {false, build.error};
    }
    const DWORD error = WriteCsvFile(path.data(), build.bytes);
    return {error == ERROR_SUCCESS, error};
}
