#include "first.h"

// ====================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ======================

#include <vector>
#include <string>

// Заголовки колонок в порядке следования в отчёте
static const std::vector<std::string> kColumnHeaders = {
    "DID", "MNEMONIC", "ACCESS", "READ_STATUS", "SIZE_ACTUAL",
    "COMPLIANCE", "SIZE_EXPECTED", "DEFAULT_WRITE", "EXTENDED_WRITE"
};

// true = выравнивание по правому краю (для чисел), false = по левому (для текста)
static const std::vector<bool> kColumnRightAlign = {
    false, false, false, true, true, false, true, false, false
};

// Ширина колонки = максимум из заголовка и всех значений в этой колонке
std::vector<int> ComputeColumnWidths(const std::vector<std::vector<std::string>>& rows)
{
    std::vector<int> widths(kColumnHeaders.size());
    for (size_t c = 0; c < kColumnHeaders.size(); c++)
        widths[c] = (int)kColumnHeaders[c].size();

    for (const auto& row : rows)
        for (size_t c = 0; c < row.size() && c < widths.size(); c++)
            if ((int)row[c].size() > widths[c])
                widths[c] = (int)row[c].size();

    return widths;
}

// Дополняет значение пробелами до нужной ширины
std::string PadValue(const std::string& value, int width, bool rightAlign)
{
    int padding = width - (int)value.size();
    if (padding < 0) padding = 0;
    return rightAlign ? (std::string(padding, ' ') + value)
                       : (value + std::string(padding, ' '));
}

// Строка таблицы: "| знач1 | знач2 | ... |"
std::string BuildTableRow(const std::vector<std::string>& values, const std::vector<int>& widths)
{
    std::string line = "|";
    for (size_t c = 0; c < values.size(); c++)
    {
        bool rightAlign = (c < kColumnRightAlign.size()) ? kColumnRightAlign[c] : false;
        line += " " + PadValue(values[c], widths[c], rightAlign) + " |";
    }
    return line;
}

// Разделительная линия из "-", по ширине совпадает со строкой таблицы
std::string BuildSeparatorLine(const std::vector<int>& widths)
{
    int total = 1; // крайняя левая "|"
    for (int w : widths)
        total += w + 3; // пробел + значение + пробел + "|"
    return std::string(total, '-');
}




// Пишет всю таблицу целиком: верхняя граница, заголовок, граница, данные, граница
void WriteTableToReport(native_int reportHandle, const std::vector<std::vector<std::string>>& rows)
{
    std::vector<int> widths = ComputeColumnWidths(rows);
    std::string separator = BuildSeparatorLine(widths);

    const char* sepLine[1] = { separator.c_str() };
    app.write_text_file_line_string_array(reportHandle, sepLine, 1);

    std::string headerLine = BuildTableRow(kColumnHeaders, widths);
    const char* headerArr[1] = { headerLine.c_str() };
    app.write_text_file_line_string_array(reportHandle, headerArr, 1);

    app.write_text_file_line_string_array(reportHandle, sepLine, 1);

    for (const auto& row : rows)
    {
        std::string line = BuildTableRow(row, widths);
        const char* lineArr[1] = { line.c_str() };
        app.write_text_file_line_string_array(reportHandle, lineArr, 1);
    }

    app.write_text_file_line_string_array(reportHandle, sepLine, 1);
}



//===================================================================================



bool EnterExtendedSession(int udsHandle, const DelaySettings& delays)
{
    log("Переход в Extended Session...");
    int result = rtlUIDiagnostics.tsdiag_session_control(udsHandle, 0x03);
    app.wait(delays.afterSessionChange, "");

    if (result != 0)
    {
        log("Не удалось перейти в Extended Session, result=%d", result);
        return false;
    }
    log("Extended Session OK");
    return true;
}

bool ReadDID(int udsHandle, const DidRefEntry& entry, u8* outData, int& outSize)
{
    outSize = 0xFFF;
    return rtlUIDiagnostics.tsdiag_can_read_data_by_identifier(
        udsHandle, entry.did, outData, &outSize) == 0;
}

void TryWriteInSession(int udsHandle, const DidRefEntry& entry, char* outStatus, bool useExtended)
{
    const char* sessionName = useExtended ? "Extended" : "Default";
    log("Попытка записи DID 0x%04X в %s Session", entry.did, sessionName);

    u8 writeData[0xFFF] = {0};
    bool isAsciiOrList = (entry.data_type == "ASCII");

    for (int i = 0; i < entry.length_bytes && i < 0xFFF; i++)
        writeData[i] = isAsciiOrList ? 0x7A : 0x1;

    int writeStatus = useExtended ?
        rtlUIDiagnostics.tsdiag_can_write_data_by_identifier(udsHandle, entry.did, writeData, entry.length_bytes) :
        rtlUIDiagnostics.tsdiag_write_data_by_identifier(udsHandle, entry.did, writeData, entry.length_bytes);

    if (writeStatus == 0)
    {
        strcpy(outStatus, useExtended ? "WRITE_OK_EXT" : "WRITE_OK");
        log("Успешно записано в %s (DID 0x%04X)", sessionName, entry.did);
    }
    else
    {
        strcpy(outStatus, useExtended ? "WRITE_FAIL_EXT" : "WRITE_FAIL");
        log("Ошибка записи в %s (DID 0x%04X, status=%d)", sessionName, entry.did, writeStatus);
    }
}

void WriteReportHeader(native_int reportHandle)
{
    const char* header[1] = {"DID\tMNEMONIC\tACCESS_DEFAULT_SESSION\tREAD_STATUS\tSIZE_ACTUAL\tDEFAULT_READING_COMPLIANCE WITH DOCUMENTATION\tSIZE_EXPECTED\tDEFAULT_WRITE\tEXTENDED_READ_STATUS\tEXTENDED_READ_SIZE\tEXTENDED_WRITE"};
    app.write_text_file_line_string_array(reportHandle, header, 1);
}

void AppendDIDResultToReport(native_int reportHandle, const DidRefEntry &entry,int readStatus, int readSize,const char* defaultWrite, //>>
int extendedReadStatus, int extendedReadSize,const char* extendedWrite)
std::vector<std::string> BuildDIDResultRow(const DidRefEntry& entry,
                                            int readStatus, int readSize,
                                            const std::string& defaultWrite,
                                            const std::string& extendedWrite)
{
    const char* compliance = (entry.access_default_session == "R" && readStatus == 0) ? "OK" : "FAIL";

    char didStr[16];
    sprintf(didStr, "0x%04X", entry.did);

    return {
        didStr,
        entry.mnemonic,
        entry.access_default_session,
        std::to_string(readStatus),
        std::to_string(readSize),
        compliance,
        std::to_string(entry.length_bytes),
        defaultWrite,
        extendedWrite
    };
}
void WriteTotalStats(native_int reportHandle, const CheckStats& stats)
{
    char totalLine[200];
    sprintf(totalLine, "TOTAL\t\tACCESS_OK=%d\tACCESS_FAIL=%d\tSIZE_OK=%d\tSIZE_FAIL=%d",
            stats.accessMatch, stats.accessMismatch, stats.sizeMatch, stats.sizeMismatch);

    const char* totalArray[1] = {totalLine};
    app.write_text_file_line_string_array(reportHandle, totalArray, 1);

    log("=== ИТОГ: доступ OK=%d FAIL=%d | размер OK=%d MISMATCH=%d ===",
        stats.accessMatch, stats.accessMismatch, stats.sizeMatch, stats.sizeMismatch);
}

// ====================== MAIN ======================
void first()
{
    log("=== Запуск анализа DID ===");

    DelaySettings delays;
    // Настройка задержек
    delays.afterUdsCreate = 1000;
    delays.afterSessionChange = 1300;
    delays.afterRead = 600;
    delays.afterWrite = 750;
    delays.betweenDIDs = 650;

    auto didTable = loadDidTable();
    log("Загружено DID: %zu", didTable.size());

    if (didTable.empty()) {
        log("Таблица DID пуста!");
        app.terminate_application();
        return;
    }

    native_int reportHandle = -1;
    if (0 != app.write_text_file_start(".\\DID_Report.txt", &reportHandle)) {
        log("Не удалось создать отчет");
        app.terminate_application();
        return;
    }

    //WriteReportHeader(reportHandle);

    CheckStats stats = {};
    std::vector<DIDResult> results;

    int udsHandle = -1;
    rtlUIDiagnostics.tsdiag_can_create(&udsHandle, CH1, 0, 15, 0x78B, 1, 0x7AB, 1, 0x78B, 1);
    app.wait(delays.afterUdsCreate, "");

    log("=== Этап 1: Default Session ===");
    for (const auto& entry : didTable)
    {
        if (entry.did == 0 || entry.mnemonic.empty()) continue;

        DIDResult res;
        res.entry = entry;

        u8 readData[0xFFF];
        int readSize = 0;
        res.readStatus = ReadDID(udsHandle, entry, readData, readSize) ? 0 : -1;
        res.readSize = readSize;

        if (entry.access_default_session == "R" && res.readStatus == 0)
        {
            
            stats.accessMatch++;
            if (readSize == entry.length_bytes)
            {
                
                stats.sizeMatch++;
                char buf[32] = {};
                TryWriteInSession(udsHandle, entry, buf, false);
                res.defaultWrite = buf;
            }
            else
            {
                stats.sizeMismatch++;
                res.defaultWrite = "SKIP_SIZE";
            }
        }
        else
        {
            stats.accessMismatch++;
            res.defaultWrite = "SKIP_ACCESS";
        }

        results.push_back(res);
        app.wait(delays.betweenDIDs, "");
    }

    log("=== Этап 2: Extended Session ===");
    if (EnterExtendedSession(udsHandle, delays))
    {
        for (auto& res : results)
        {
            u8 extReadData[0xFFF];
            int extReadSize = 0;
            res.extendedReadStatus = ReadDID(udsHandle, res.entry, extReadData, extReadSize) ? 0 : -1;
            res.extendedReadSize = extReadSize;

        log("DID 0x%04X: extended read status=%d size=%d",
            res.entry.did, res.extendedReadStatus, res.extendedReadSize);

        app.wait(delays.afterRead, "");

            char buf[32] = {};
            TryWriteInSession(udsHandle, res.entry, buf, true);
            res.extendedWrite = buf;
            app.wait(delays.betweenDIDs, "");
        }
    }

std::vector<std::vector<std::string>> tableRows;
tableRows.reserve(results.size());

for (const auto& res : results)
{
    tableRows.push_back(BuildDIDResultRow(
        res.entry, res.readStatus, res.readSize,
        res.defaultWrite, res.extendedWrite));
}

WriteTableToReport(reportHandle, tableRows);
WriteTotalStats(reportHandle, stats);   // итоговую строку пишем как раньше, отдельным блоком
app.write_text_file_end(reportHandle);

    log("=== Отчет сохранен: DID_Report.txt ===");
    app.terminate_application();
}
