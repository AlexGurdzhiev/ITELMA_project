#include "DidRefC.h"

void TryWriteDID(int udsHandle, const DidRefEntry& entry, char* outStatus, bool useExtended = false)
{
    const char* sessionName = useExtended ? "Extended" : "Default";

    log("Попытка записи DID 0x%04X в %s Session", entry.did, sessionName);

    u8 writeData[0xFFF] = {0};
    bool isAsciiOrList = (entry.data_type == "ASCII" || entry.data_type == "List");

    for (int i = 0; i < entry.length_bytes && i < 0xFFF; i++)
        writeData[i] = isAsciiOrList ? 0x7A : 0x00;

    int writeStatus = rtlUIDiagnostics.tsdiag_write_data_by_identifier(
        udsHandle, entry.did, writeData, entry.length_bytes);

    if (writeStatus == 0)
    {
        strcpy(outStatus, useExtended ? "WRITE_OK_EXT" : "WRITE_OK");
        log("Успешно записано в %s Session (DID 0x%04X)", sessionName, entry.did);
    }
    else
    {
        strcpy(outStatus, useExtended ? "WRITE_FAIL_EXT" : "WRITE_FAIL");
        log("Не удалось записать в %s Session (DID 0x%04X, status=%d)", 
            sessionName, entry.did, writeStatus);
    }
}

bool CheckDefaultAccess(const DidRefEntry& entry, int readStatus, int readSize, CheckStats& stats)
{
    if (entry.access_default_session == "R" && readStatus == 0)
    {
        stats.accessMatch++;
        if (readSize == entry.length_bytes)
        {
            stats.sizeMatch++;
            return true;
        }
        else
        {
            stats.sizeMismatch++;
            log("DID 0x%04X: размер не совпадает (получено=%d, ожидается=%d)", 
                entry.did, readSize, entry.length_bytes);
            return false;
        }
    }
    else
    {
        stats.accessMismatch++;
        log("DID 0x%04X: нет доступа в Default Session (access=%s, status=%d)", 
            entry.did, entry.access_default_session.c_str(), readStatus);
        return false;
    }
}

bool Extended_Session(int udsHandle, const DidRefEntry& entry)
{
    log("Переход в Extended Session для DID 0x%04X", entry.did);
    
    int result = rtlUIDiagnostics.tsdiag_session_control(udsHandle, 0x03);
    app.wait(300, "");  

    if (result != 0)
    {
        log("Не удалось перейти в Extended Session, result=%d", result);
        return false;
    }

    log("Extended Session OK");

    u8 writeData[0xFFF] = {0};
    bool isAsciiOrList = (entry.data_type == "ASCII" || entry.data_type == "List");

    for (int i = 0; i < entry.length_bytes && i < 0xFFF; i++)
        writeData[i] = isAsciiOrList ? 0x7A : 0x00;

    int status = rtlUIDiagnostics.tsdiag_write_data_by_identifier(
        udsHandle, entry.did, writeData, entry.length_bytes);

    app.wait(300, "");

    if (status == 0)
    {
        log("Extended WRITE OK для DID 0x%04X", entry.did);
        return true;
    }

    log("Extended WRITE FAIL для DID 0x%04X, status=%d", entry.did, status);
    return false;
}

void first()
{
    log("=== first() started ===");

    std::vector<DidRefEntry> didTable = loadDidTable();
    log("Всего DID в таблице: %zu", didTable.size());

    CheckStats stats = {};
    int udsHandle = -1;

    int status = rtlUIDiagnostics.tsdiag_can_create(&udsHandle, CH1, 0, 15, 0x78B, 1, 0x7AB, 1, 0x78B, 1);
    log("UDS create status = %d", status);

    app.wait(300, "");

    for (const auto& entry : didTable)
    {
        if (entry.did == 0 || entry.mnemonic.empty())
            continue;

        log("=== Обработка DID 0x%04X (%s) ===", entry.did, entry.mnemonic.c_str());

        char defaultWriteStatus[32] = "N/A";
        char extendedWriteStatus[32] = "N/A";

        // Чтение в Default Session
        u8 readData[0xFFF] = {0};
        int readDataSize = 0xFFF;

        status = rtlUIDiagnostics.tsdiag_can_read_data_by_identifier(udsHandle, entry.did, readData, &readDataSize);

        bool canReadDefault = CheckDefaultAccess(entry, status, readDataSize, stats);

        // Попытка записи в Default
        if (canReadDefault)
        {
            TryWriteDID(udsHandle, entry, defaultWriteStatus, false);
        }
        else
        {
            strcpy(defaultWriteStatus, "NO_ACCESS");
        }

        // Если Default не прошёл — пробуем Extended
        if (strcmp(defaultWriteStatus, "WRITE_OK") != 0)
        {
            bool extSuccess = Extended_Session(udsHandle, entry);
            strcpy(extendedWriteStatus, extSuccess ? "WRITE_OK_EXT" : "WRITE_FAIL_EXT");
        }
        else
        {
            strcpy(extendedWriteStatus, "SKIP_Default_OK");
        }

        log("Результат DID 0x%04X → Default: %s | Extended: %s", 
            entry.did, defaultWriteStatus, extendedWriteStatus);

        app.wait(150, "");
    }

    // Итог
    log("=== ИТОГОВАЯ СТАТИСТИКА ===");
    log("Access Match: %d | Mismatch: %d", stats.accessMatch, stats.accessMismatch);
    log("Size Match: %d | Mismatch: %d", stats.sizeMatch, stats.sizeMismatch);

    app.wait(100, "");
    app.terminate_application();
}
