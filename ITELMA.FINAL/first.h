// first.h
#pragma once

#include "DidRefC.h"
#include <vector>
#include <string>

// Если CheckStats не видно — определяем его здесь
#ifndef CheckStats
struct CheckStats
{
    int accessMatch = 0;
    int accessMismatch = 0;
    int sizeMatch = 0;
    int sizeMismatch = 0;
};
#endif

// ====================== НАСТРОЙКИ ЗАДЕРЖЕК ======================
struct DelaySettings
{
    int afterUdsCreate = 1000;
    int afterSessionChange = 1300;
    int afterRead = 600;
    int afterWrite = 750;
    int betweenDIDs = 650;
};
struct DIDResult
{
    DidRefEntry entry;
    int readStatus = -1;
    int readSize = 0;

    int extendedReadStatus = -1;
    int extendedReadSize  = 0;

    int extendedWriteStatus = -1;   
    
    std::string defaultWrite = "N/A";
    std::string extendedWrite = "N/A";
};
// ====================== ПРОТОТИПЫ ======================
std::vector<DidRefEntry> loadDidTable();

bool EnterExtendedSession(int udsHandle, const DelaySettings& delays);
bool ReadDID(int udsHandle, const DidRefEntry& entry, u8* outData, int& outSize);
void TryWriteInSession(int udsHandle, const DidRefEntry& entry, char* outStatus, bool useExtended);

void WriteReportHeader(native_int reportHandle);
void AppendDIDResultToReport(native_int reportHandle, const DidRefEntry& entry,
                             int readStatus, int readSize,
                             const char* defaultWrite, const char* extendedWrite);
void WriteTotalStats(native_int reportHandle, const CheckStats& stats);

void first();
