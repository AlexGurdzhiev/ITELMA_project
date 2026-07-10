#include "DidRefC.h"

struct CheckStats
{
    int accessMatch = 0;
    int accessMismatch = 0;
    int sizeMatch = 0;
    int sizeMismatch = 0;
};


void TryWriteDID(int udsHandle, const DidRefEntry& entry, char* outStatus)
{
    u8 writeData[0xFFF] = {0};

    if (entry.data_type == "ASCII" || entry.data_type == "List")
    {
        for (int i = 0; i < entry.length_bytes; i++)
            writeData[i] = 0x7A;

        int writeStatus = rtlUIDiagnostics.tsdiag_can_write_data_by_identifier(
            udsHandle, entry.did, writeData, entry.length_bytes);

        strcpy(outStatus, (writeStatus == 0) ? "WRITE_OK" : "WRITE_FAIL");
        return;
    }

    if (entry.data_type == "HEXA" || entry.data_type == "Numerical")
    {
        for (int i = 0; i < entry.length_bytes; i++)
            writeData[i] = 0x00;

        int writeStatus = rtlUIDiagnostics.tsdiag_can_write_data_by_identifier(
            udsHandle, entry.did, writeData, entry.length_bytes);

        strcpy(outStatus, (writeStatus == 0) ? "WRITE_OK" : "WRITE_FAIL");
        return;
    }

    strcpy(outStatus, "UNSUPPORTED_TYPE");
}


void Default_ParsData()
{
    std::vector<DidRefEntry> didTable = loadDidTable();
    log("Всего DID в таблице: %zu", didTable.size());
    log("=== Начало проверки доступа к DID в default session ===");
    log("==Состояние R - соответвует доступно для чтения в default session, status = 0, читает на шине данных, ==");

    CheckStats stats;
    native_int reportHandle;

    if (0 != app.write_text_file_start(".\\DID_Report.txt", &reportHandle))
    {
        log("Ошибка создания отчета");
        return;
    }

    const char* descLine[1];
    char descText[] = "Скрипт проверки документации статус ACCESS/SIZE/WRITE в default session";
    descLine[0] = descText;
    app.write_text_file_line_string_array(reportHandle, descLine, 1);

    // Заголовок таблицы — ровно 7 колонок, без "\n" внутри
    const char* header[1];
    char headerText[] = "DID\tMNEMONIC\tACCESS\tDEFAULT_READ_STATUS\tSIZE_ACTUAL\tSIZE_EXPECTED\tDEFAULT_WRITE_STATUS";
    header[0] = headerText;
    app.write_text_file_line_string_array(reportHandle, header, 1);

    int udsHandle = -1;
    int status = rtlUIDiagnostics.tsdiag_can_create(&udsHandle, CH1, 0, 15, 0x78B, 1, 0x7AB, 1, 0x78B, 1);
    log("create status = %d", status);
    app.wait(300, "");
//.................................................................................................................................
//.......................Проверка доступа к DID в default session, проверка статуса status получаемого из шины......................................................................................
    for (const auto& entry : didTable)
    {
        if (entry.did == 0 || entry.mnemonic.empty())
            continue;//если строка пустая, то пропускаем

        u8 readData[0xFFF];
        int readDataSize = 0xFFF;
        status = rtlUIDiagnostics.tsdiag_can_read_data_by_identifier(udsHandle, entry.did, readData, &readDataSize);

        // Единый статус записи для этой строки отчёта, по умолчанию "N/A"
        char writeStatusStr[64] = "N/A";
        bool size_ok = false;

        if (entry.access_default_session == "R" && status == 0)
        {
            stats.accessMatch++;
            size_ok = (readDataSize == entry.length_bytes);

           if (size_ok)
{
    stats.sizeMatch++;

    TryWriteDID(udsHandle, entry, writeStatusStr);// проверяем возможность записи в DID, если тип данных поддерживается
    log("DID 0x%04X (%s): write result = %s",
        entry.did,
        entry.mnemonic.c_str(),
        writeStatusStr);
}
            else
            {
                stats.sizeMismatch++;
                strcpy(writeStatusStr, "SKIP_SIZE_MISMATCH");
                log("НЕ СОВПАДАЕТ: DID 0x%04X (%s) - size: получено=%d эталон=%d",
                    entry.did, entry.mnemonic.c_str(), readDataSize, entry.length_bytes);
            }
        }
        else
        {
            stats.accessMismatch++;
            strcpy(writeStatusStr, "SKIP_ACCESS");
            log("НЕ СОВПАДАЕТ: DID 0x%04X (%s) - access=%s, status=%d",
                entry.did, entry.mnemonic.c_str(), entry.access_default_session.c_str(), status);
        }

        // Ровно ОДНА строка на DID, ровно 7 колонок, всегда одного формата
        char txtLine[256];
       sprintf(txtLine, "0x%04X\t%s\t%s\t%d\t%d\t%d\t%s",
    entry.did,
    entry.mnemonic.c_str(),
    entry.access_default_session.c_str(),
    status,
    readDataSize,
    entry.length_bytes,
    writeStatusStr);
        const char* txtArray[1];
        txtArray[0] = txtLine;
        app.write_text_file_line_string_array(reportHandle, txtArray, 1);

        app.wait(100, "");
    }

    log("=== ИТОГ: доступ OK=%d FAIL=%d | размер OK=%d MISMATCH=%d ===",
        stats.accessMatch, stats.accessMismatch, stats.sizeMatch, stats.sizeMismatch);

    char totalLine[128];
    sprintf(totalLine, "TOTAL\tACCESS_OK=%d\tACCESS_FAIL=%d\tSIZE_OK=%d\tSIZE_FAIL=%d",
        stats.accessMatch, stats.accessMismatch, stats.sizeMatch, stats.sizeMismatch);

    const char* totalArray[1];
    totalArray[0] = totalLine;
    app.write_text_file_line_string_array(reportHandle, totalArray, 1);

    app.write_text_file_end(reportHandle);
    app.terminate_application();
}

// void Extended_Session()
// {

// }




void first()
{
    Default_ParsData();
    app.wait(100, "");
    app.terminate_application();
}
