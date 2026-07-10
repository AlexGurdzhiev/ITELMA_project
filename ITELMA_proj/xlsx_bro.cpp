#include "DidRefC.h"

struct CheckStats
{
    int accessMatch = 0;
    int accessMismatch = 0;
    int sizeMatch = 0;
    int sizeMismatch = 0;
};

struct ReportRow
{
    unsigned short did;
    std::string mnemonic;
    std::string access;
    int status;
    int sizeActual;
    int sizeExpected;
    std::string writeStatus;
};

// ---------- ЕДИНЫЙ ПРОХОД ПО ШИНЕ ----------
// Данные собираются один раз, потом используются и для TXT, и для XLSX
std::vector<ReportRow> CollectDidReportData(CheckStats& stats)
{
    std::vector<ReportRow> rows;
    std::vector<DidRefEntry> didTable = loadDidTable();

    log("Всего DID в таблице: %zu", didTable.size());
    log("=== Начало проверки доступа к DID в default session ===");

    int udsHandle = -1;
    int status = rtlUIDiagnostics.tsdiag_can_create(&udsHandle, CH1, 0, 15, 0x78B, 1, 0x7AB, 1, 0x78B, 1);
    log("create status = %d", status);
    app.wait(300, "");

    for (const auto& entry : didTable)
    {
        if (entry.did == 0 || entry.mnemonic.empty())
            continue;

        u8 readData[0xFFF];
        int readDataSize = 0xFFF;
        status = rtlUIDiagnostics.tsdiag_can_read_data_by_identifier(udsHandle, entry.did, readData, &readDataSize);

        ReportRow row;
        row.did = entry.did;
        row.mnemonic = entry.mnemonic;
        row.access = entry.access_default_session;
        row.status = status;
        row.sizeActual = readDataSize;
        row.sizeExpected = entry.length_bytes;
        row.writeStatus = "N/A";

        if (entry.access_default_session == "R" && status == 0)
        {
            stats.accessMatch++;
            bool size_ok = (readDataSize == entry.length_bytes);

            if (size_ok)
            {
                stats.sizeMatch++;
                u8 writeData[0xFFF] = {0};

                if (entry.data_type == "ASCII" || entry.data_type == "List")
                {
                    for (int i = 0; i < entry.length_bytes; i++) writeData[i] = 0x7A;

                    int writeDataSize = entry.length_bytes;
                    int writeStatus = rtlUIDiagnostics.tsdiag_can_write_data_by_identifier(
                        udsHandle, entry.did, writeData, writeDataSize);

                    row.writeStatus = (writeStatus == 0) ? "WRITE_OK" : "WRITE_FAIL";
                    log("DID 0x%04X: WRITE status = %d -> %s", entry.did, writeStatus, row.writeStatus.c_str());
                }
                else if (entry.data_type == "HEXA" || entry.data_type == "Numerical")
                {
                    for (int i = 0; i < entry.length_bytes; i++) writeData[i] = 0x00;

                    int writeDataSize = entry.length_bytes;
                    int writeStatus = rtlUIDiagnostics.tsdiag_can_write_data_by_identifier(
                        udsHandle, entry.did, writeData, writeDataSize);

                    row.writeStatus = (writeStatus == 0) ? "WRITE_OK" : "WRITE_FAIL";
                    log("DID 0x%04X: WRITE status = %d -> %s", entry.did, writeStatus, row.writeStatus.c_str());
                }
                else
                {
                    row.writeStatus = "UNSUPPORTED_TYPE";
                    log("DID 0x%04X (%s): data_type=%s не поддерживается для записи",
                        entry.did, entry.mnemonic.c_str(), entry.data_type.c_str());
                }
            }
            else
            {
                stats.sizeMismatch++;
                row.writeStatus = "SKIP_SIZE_MISMATCH";
                log("НЕ СОВПАДАЕТ: DID 0x%04X (%s) - size: получено=%d эталон=%d",
                    entry.did, entry.mnemonic.c_str(), readDataSize, entry.length_bytes);
            }
        }
        else
        {
            stats.accessMismatch++;
            row.writeStatus = "SKIP_ACCESS";
            log("НЕ СОВПАДАЕТ: DID 0x%04X (%s) - access=%s, status=%d",
                entry.did, entry.mnemonic.c_str(), entry.access_default_session.c_str(), status);
        }

        rows.push_back(row);
        app.wait(100, "");
    }

    log("=== ИТОГ: доступ OK=%d FAIL=%d | размер OK=%d MISMATCH=%d ===",
        stats.accessMatch, stats.accessMismatch, stats.sizeMatch, stats.sizeMismatch);

    return rows;
}

// ---------- TXT ОТЧЁТ ----------
void WriteTxtReport(const std::vector<ReportRow>& rows, const CheckStats& stats)
{
    native_int reportHandle;
    if (0 != app.write_text_file_start(".\\DID_Report.txt", &reportHandle))
    {
        log("Ошибка создания TXT отчета");
        return;
    }

    const char* header[1];
    char headerText[] = "DID\tMNEMONIC\tACCESS\tSTATUS\tSIZE_ACTUAL\tSIZE_EXPECTED\tDEFAULT_WRITE_STATUS";
    header[0] = headerText;
    app.write_text_file_line_string_array(reportHandle, header, 1);

    for (const auto& row : rows)
    {
        char txtLine[256];
        sprintf(txtLine, "0x%04X\t%s\t%s\t%d\t%d\t%d\t%s",
            row.did, row.mnemonic.c_str(), row.access.c_str(), row.status,
            row.sizeActual, row.sizeExpected, row.writeStatus.c_str());

        const char* txtArray[1];
        txtArray[0] = txtLine;
        app.write_text_file_line_string_array(reportHandle, txtArray, 1);
    }

    char totalLine[128];
    sprintf(totalLine, "TOTAL\tACCESS_OK=%d\tACCESS_FAIL=%d\tSIZE_OK=%d\tSIZE_FAIL=%d",
        stats.accessMatch, stats.accessMismatch, stats.sizeMatch, stats.sizeMismatch);
    const char* totalArray[1];
    totalArray[0] = totalLine;
    app.write_text_file_line_string_array(reportHandle, totalArray, 1);

    app.write_text_file_end(reportHandle);
}

// ---------- XLSX ОТЧЁТ ----------
// !!! Имена app.excel_* — предполагаемые по аналогии с app.excel_load из вашего кода.
// !!! Свериться с реальным API (DidRefC.h / SDK) и поправить при необходимости.
void WriteXlsxReport(const std::vector<ReportRow>& rows, const CheckStats& stats)
{
    void* excelFile = nullptr;
    int sheetNumber = 0;

    if (app.excel_create(".\\DID_Report.xlsx", &excelFile) != 0)
    {
        log("Ошибка создания XLSX отчета");
        return;
    }

    // --- Заголовок: каждая колонка своим вызовом, своя ячейка ---
    const char* columnNames[7] = {
        "DID", "MNEMONIC", "ACCESS", "STATUS",
        "SIZE_ACTUAL", "SIZE_EXPECTED", "DEFAULT_WRITE_STATUS"
    };

    for (int col = 0; col < 7; col++)
    {
        app.excel_set_cell_value(excelFile, sheetNumber, 0, col, columnNames[col]);
    }

    // --- Данные: строка на DID, поле -> своя колонка ---
    int rowIndex = 1;
    for (const auto& row : rows)
    {
        char didStr[16];
        sprintf(didStr, "0x%04X", row.did);

        char statusStr[16];
        sprintf(statusStr, "%d", row.status);

        char sizeActualStr[16];
        sprintf(sizeActualStr, "%d", row.sizeActual);

        char sizeExpectedStr[16];
        sprintf(sizeExpectedStr, "%d", row.sizeExpected);

        app.excel_set_cell_value(excelFile, sheetNumber, rowIndex, 0, didStr);
        app.excel_set_cell_value(excelFile, sheetNumber, rowIndex, 1, row.mnemonic.c_str());
        app.excel_set_cell_value(excelFile, sheetNumber, rowIndex, 2, row.access.c_str());
        app.excel_set_cell_value(excelFile, sheetNumber, rowIndex, 3, statusStr);
        app.excel_set_cell_value(excelFile, sheetNumber, rowIndex, 4, sizeActualStr);
        app.excel_set_cell_value(excelFile, sheetNumber, rowIndex, 5, sizeExpectedStr);
        app.excel_set_cell_value(excelFile, sheetNumber, rowIndex, 6, row.writeStatus.c_str());

        rowIndex++;
    }

    // --- Итоговая строка ---
    char accOk[16], accFail[16], szOk[16], szFail[16];
    sprintf(accOk, "%d", stats.accessMatch);
    sprintf(accFail, "%d", stats.accessMismatch);
    sprintf(szOk, "%d", stats.sizeMatch);
    sprintf(szFail, "%d", stats.sizeMismatch);

    app.excel_set_cell_value(excelFile, sheetNumber, rowIndex, 0, "TOTAL");
    app.excel_set_cell_value(excelFile, sheetNumber, rowIndex, 1, "ACCESS_OK");
    app.excel_set_cell_value(excelFile, sheetNumber, rowIndex, 2, accOk);
    app.excel_set_cell_value(excelFile, sheetNumber, rowIndex, 3, "ACCESS_FAIL");
    app.excel_set_cell_value(excelFile, sheetNumber, rowIndex, 4, accFail);
    app.excel_set_cell_value(excelFile, sheetNumber, rowIndex, 5, "SIZE_OK");
    app.excel_set_cell_value(excelFile, sheetNumber, rowIndex, 6, szOk);

    rowIndex++;
    app.excel_set_cell_value(excelFile, sheetNumber, rowIndex, 5, "SIZE_FAIL");
    app.excel_set_cell_value(excelFile, sheetNumber, rowIndex, 6, szFail);

    // --- Автоширина колонок: подгоняем каждую под содержимое ---
    for (int col = 0; col < 7; col++)
    {
        app.excel_autofit_column(excelFile, sheetNumber, col);
    }

    app.excel_save(excelFile);
    app.excel_close(excelFile);
}

// ---------- ГЛАВНАЯ ФУНКЦИЯ ----------
void Default_ParsData()
{
    CheckStats stats;
    std::vector<ReportRow> rows = CollectDidReportData(stats);

    WriteTxtReport(rows, stats);
    WriteXlsxReport(rows, stats);
}

void first()
{
    Default_ParsData();
    app.wait(100, "");
    app.terminate_application();
}
