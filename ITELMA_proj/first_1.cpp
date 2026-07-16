#include "DidRefC.h"

struct CheckStats
{
    int accessMatch = 0;
    int accessMismatch = 0;
    int sizeMatch = 0;
    int sizeMismatch = 0;
};
bool Extended_Session(int udsHandle, const DidRefEntry& entry)
{
    log("Переход в Extended Session для DID 0x%04X", entry.did);
    
    int result = rtlUIDiagnostics.tsdiag_session_control(udsHandle, 0x03);
    app.wait(300, "");  

    //рабить

    if (result != 0)
    {
        log("Не удалось перейти в Extended Session, result=%d", result);
        return false;
    }

    log("Extended Session OK");

    u8 writeData[0xFFF] = {0};
    bool isAsciiOrList = (entry.data_type == "ASCII" || entry.data_type == "List");

    for(int i = 0; i < entry.length_bytes && i < 0xFFF; i++)
        writeData[i] = isAsciiOrList ? 0x7A : 0x00;

    int status = rtlUIDiagnostics.tsdiag_can_write_data_by_identifier(
        udsHandle,
        entry.did,
        writeData,
        entry.length_bytes);

    app.wait(300, "");

    if(status == 0)
    {
        log("Extended WRITE OK DID 0x%04X", entry.did);
        return true;
    }

    log("Extended WRITE FAIL DID 0x%04X, status=%d", entry.did, status);
    return false;
}

// ===================================================================

// Универсальная функция записи
void TryWriteDID(int udsHandle, const DidRefEntry& entry, char* outStatus, bool useExtended = false)
{
    const char* sessionName = useExtended ? "Extended" : "Default";

    log("Попытка записи DID 0x%04X в %s Session", entry.did, sessionName);

    u8 writeData[0xFFF] = {0};
    bool isAsciiOrList = (entry.data_type == "ASCII" || entry.data_type == "List");

    for(int i = 0; i < entry.length_bytes && i < 0xFFF; i++)
        writeData[i] = isAsciiOrList ? 0x7A : 0x00;

    int writeStatus = rtlUIDiagnostics.tsdiag_write_data_by_identifier(
        udsHandle,
        entry.did,
        writeData,
        entry.length_bytes);

    if(writeStatus == 0)
    {
        strcpy(outStatus, useExtended ? "WRITE_OK_EXT" : "WRITE_OK");
        log("Успешно записано в %s Session (DID 0x%04X)", sessionName, entry.did);
        return;
    }

    strcpy(outStatus, useExtended ? "WRITE_FAIL_EXT" : "WRITE_FAIL");
    log("Не удалось записать в %s Session (DID 0x%04X, status=%d)", 
        sessionName, entry.did, writeStatus);
}
void Default_ParsData()
{
    std::vector<DidRefEntry> didTable = loadDidTable();
    log("Всего DID в таблице: %zu", didTable.size());

    CheckStats stats;
    native_int reportHandle;

    if (0 != app.write_text_file_start(".\\DID_Report.txt", &reportHandle))
    {
        log("Ошибка создания отчета");
        return;
    }

    // Заголовок одной таблицы
    const char* header[1];
    char headerText[] = "DID\tMNEMONIC\tACCESS\tREAD_STATUS\tSIZE_ACTUAL\tSIZE_EXPECTED\tDEFAULT_WRITE\tEXTENDED_WRITE";
    header[0] = headerText;
    app.write_text_file_line_string_array(reportHandle, header, 1);//это отдельно

    int udsHandle = -1;
    int status = rtlUIDiagnostics.tsdiag_can_create(&udsHandle, CH1, 0, 15, 0x78B, 1, 0x7AB, 1, 0x78B, 1);
    log("UDS create status = %d", status);
    app.wait(800, "");

    log("=== Этап 1: Default Session ===");

    // Первый проход - Default
    for (const auto& entry : didTable)
    {
        if (entry.did == 0 || entry.mnemonic.empty()) continue;

        u8 readData[0xFFF];
        int readDataSize = 0xFFF;
        status = rtlUIDiagnostics.tsdiag_can_read_data_by_identifier(udsHandle, entry.did, readData, &readDataSize);

        char defaultWrite[32] = "N/A";
        char extendedWrite[32] = "N/A";

        if (entry.access_default_session == "R" && status == 0)
        {
            stats.accessMatch++;
            if (readDataSize == entry.length_bytes)
            {
                stats.sizeMatch++;
                TryWriteDID(udsHandle, entry, defaultWrite, false); // Default
                
            }
            else
            {
                stats.sizeMismatch++;
                strcpy(defaultWrite, "SKIP_SIZE");
            }
        }
        else
        {
            stats.accessMismatch++;
            strcpy(defaultWrite, "SKIP_ACCESS");
        }

        // Записываем строку с результатами Default (Extended пока N/A)
        char txtLine[512];
        sprintf(txtLine, "0x%04X\t%s\t%s\t%d\t%d\t%d\t%s\t%s",
            entry.did, entry.mnemonic.c_str(), entry.access_default_session.c_str(),
            status, readDataSize, entry.length_bytes, defaultWrite, extendedWrite);

        const char* txtArray[1] = {txtLine};
        app.write_text_file_line_string_array(reportHandle, txtArray, 1);

        app.wait(500, "");
    }

    // Второй проход - Extended
    log("=== Этап 2: Extended Session ===");
    app.wait(1000, "");

    int sessionResult = rtlUIDiagnostics.tsdiag_session_control(udsHandle, 0x03);
    log("Переход в Extended Session: %s", sessionResult == 0 ? "OK" : "FAIL");
    app.wait(500, "");

    // Здесь просто логируем Extended, т.к. обновить предыдущие строки сложно
    for (const auto& entry : didTable)
    {
        if (entry.did == 0 || entry.mnemonic.empty()) continue;

        char extendedWrite[32] = "N/A";
        TryWriteDID(udsHandle, entry, extendedWrite, true);

        log("DID 0x%04X → Extended: %s", entry.did, extendedWrite);

        app.wait(500, "");
    }

    // Итог
    log("=== ИТОГ: доступ OK=%d FAIL=%d | размер OK=%d MISMATCH=%d ===",
        stats.accessMatch, stats.accessMismatch, stats.sizeMatch, stats.sizeMismatch);

    char totalLine[200];
    sprintf(totalLine, "TOTAL\t\t\t\t\t\tACCESS_OK=%d\tACCESS_FAIL=%d\tSIZE_OK=%d\tSIZE_FAIL=%d",
        stats.accessMatch, stats.accessMismatch, stats.sizeMatch, stats.sizeMismatch);

    const char* totalArray[1] = {totalLine};
    app.write_text_file_line_string_array(reportHandle, totalArray, 1);

    app.write_text_file_end(reportHandle);
    log("=== Отчет сохранен: DID_Report.txt ===");
    app.terminate_application();
}
void first()
{
    // TestData testList;
    // testList = getTestData("name_input_file");
    
    // for (auto did : testList){

    //     openDiagSession(0x01);
    //     auto result =readDID(did.ID);
    //     if (fesult.status = 0){

    //     }
    //     else if (fesult.status != 0){
    //         result = writeDID
    //     }
    // }
    
    
    Default_ParsData();
    app.wait(100, "");
    app.terminate_application();
}
