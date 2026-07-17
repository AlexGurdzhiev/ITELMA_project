#include "first.h"

// ====================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ======================

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

void WriteReportHeader(native_int reportHandle)// делает заголовок reportHandle - 
{
    const char* header[1] = {"DID\tMNEMONIC\tACCESS_DEFAULT_SESSION\tREAD_STATUS\tSIZE_ACTUAL\tDEFAULT_READING_COMPLIANCE WITH DOCUMENTATION\tSIZE_EXPECTED\tDEFAULT_WRITE\tEXTENDED_WRITE"};
    app.write_text_file_line_string_array(reportHandle, header, 1);
}

void AppendDIDResultToReport(native_int reportHandle, const DidRefEntry &entry,
                             int readStatus, int readSize,
                             const char* defaultWrite, const char* extendedWrite)
{
    const char* compliance = (entry.access_default_session == "R" && readStatus == 0) ? "OK" : "FAIL";
    char txtLine[512];
    sprintf(txtLine, "0x%04X\t%s\t%s\t%d\t%d\t%s\t%d\t%s\t%s",
        entry.did,
        entry.mnemonic.c_str(),
        entry.access_default_session.c_str(),
        readStatus,
        readSize,
        compliance,              // ← ВСТАВИЛИ
        entry.length_bytes,
        defaultWrite,
        extendedWrite);

    const char* txtArray[1] = {txtLine};
    app.write_text_file_line_string_array(reportHandle, txtArray, 1);
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

    WriteReportHeader(reportHandle);

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
            DIDResult res;
            res.entry = entry;
            u8 readData[0xFFF];
            int readSize = 0;
            res.readStatus = ReadDID(udsHandle, entry, readData, readSize) ? 0 : -1;
            res.readSize = readSize;

            char buf[32] = {};
            TryWriteInSession(udsHandle, res.entry, buf, true);
            res.extendedWrite = buf;
            app.wait(delays.betweenDIDs, "");
        }
    }

    for (const auto& res : results)
    {
        AppendDIDResultToReport(reportHandle, res.entry, res.readStatus, res.readSize,
                                res.defaultWrite.c_str(), res.extendedWrite.c_str());
    }

    WriteTotalStats(reportHandle, stats);
    app.write_text_file_end(reportHandle);

    log("=== Отчет сохранен: DID_Report.txt ===");
    app.terminate_application();
}
