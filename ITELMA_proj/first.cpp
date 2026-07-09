#include "DidRefC.h"


// void Default_ParsData()
// {
// int udsHandle = -1;
// int  status;
// //status = rtlUIDiagnostics.tsdiag_can_create(&udsHandle,CH1, 0, 15, 0x78B, 1, 0x7AB, 1, 0x78B, 1);


// //переход в расширенную сессию
// //log ("status = %d", status);
// //app.wait(1000, "");
// u8 readData [0xFFF];
// int readDataSize  = 0xFFF;
// status = rtlUIDiagnostics.tsdiag_can_read_data_by_identifier(udsHandle, 0xA80A, readData, &readDataSize);
// app.wait(100, "");
// app.terminate_application();
// //[1] CAN 0x78B   
// TCAN f0 = {0,0x1,8,0,0x78B,2999235,{0x3, 0x22, 0xA8, 0xA, 0xAA, 0xAA, 0xAA, 0xAA}};
// com.transmit_can_async(&f0);
// app.wait(0, "");
// log("CAN ID = %X", f0.FIdentifier);
// }

void Default_ParsData()
{
    std::vector<DidRefEntry> didTable = loadDidTable();
   // unsigned short targetDID = 0xA80A; - хардкод сравнения
    //const DidRefEntry* pEntry = findDid(didTable, targetDID);
    log("Всего DID в таблице: %zu", didTable.size());
    log("=== Начало проверки доступа к DID в default session ===");
    log("==Состояние R - соответвует доступно для чтения в default session, status = 0, читает на шине данных, ==");
    int matchCount = 0; 
    int mismatchCount = 0;    
    s32 reportHandle;

    if (0 != app.write_text_file_start(".\\DID_Report.txt", &reportHandle))
    {
        log("Ошибка создания отчета");
        return;
    }


    // Заголовок отчета
    const char* header[1];

    app.write_text_file_line_string_array(
        reportHandle,
        header,
        1
    );


char headerText[] =
    "DID\tMNEMONIC\tACCESS\tSTATUS\tRESULT";

header[0] = headerText;
    int udsHandle = -1;
    int status;
/*
.................................................................................................................................
.......................Проверка доступа к DID в default session, проверка статуса status получаемого из шины......................................................................................
........................
.................................................................................................................................
*/
    status = rtlUIDiagnostics.tsdiag_can_create(&udsHandle, CH1, 0, 15, 0x78B, 1, 0x7AB, 1, 0x78B, 1);
    log("create status = %d", status);
    app.wait(300, "");
for(const auto& entry : didTable) {
        u8 readData[0xFFF];
        int readDataSize = 0xFFF;
        status = rtlUIDiagnostics.tsdiag_can_read_data_by_identifier(udsHandle, entry.did, readData, &readDataSize);
        log("READ status = %d, readDataSize = %d", status, readDataSize);
        app.wait(300, "");

        if (entry.did == 0 || entry.mnemonic.empty()) 
        {
            app.wait(300, "");
        // log("ПРОПУСК: похоже, запись таблицы повреждена (did=0x%04X, mnemonic='%s')",
        // entry.did, entry.mnemonic.c_str());
        continue;
        }
        app.wait(300, "");

                if (entry.access_default_session == "R" && status == 0) 
                {
                    app.wait(300, "");

                    log("OK: DID 0x%04X (%s) - access=R, status=0, совпадает", entry.did, entry.mnemonic.c_str());
                    matchCount++;
                    char txtLine[256];
                    sprintf(txtLine,"0x%04X\t%s\t%s\t%d\tOK",entry.did,entry.mnemonic.c_str(),entry.access_default_session.c_str(),status);
                    app.wait(300, "");

                const char* txtArray[1];
                txtArray[0] = txtLine;
                app.write_text_file_line_string_array(reportHandle,txtArray,1);
                app.wait(300, "");
                } 
                else {
                    log("НЕ СОВПАДАЕТ: DID 0x%04X (%s) - access=%s, status=%d",
                        entry.did, entry.mnemonic.c_str(), entry.access_default_session.c_str(), status);
                    mismatchCount++;
                    app.wait(100, "");
                     char txtLine[256];


                    sprintf(txtLine,"0x%04X\t%s\t%s\t%d\tFAIL",entry.did, entry.mnemonic.c_str(), entry.access_default_session.c_str(),status);
                    app.wait(300, "");

                    const char* txtArray[1];
                    txtArray[0] = txtLine;
                    app.write_text_file_line_string_array(
                        reportHandle,
                        txtArray,
                        1
                    );
                    }

                app.wait(100, ""); 
            }

            log("=== ИТОГ: совпало %d из %d, не совпало %d ===",matchCount,(int)didTable.size(), mismatchCount);
char totalLine[128];

sprintf(totalLine,"TOTAL\tOK=%d\tFAIL=%d",matchCount,mismatchCount);


const char* totalArray[1];
totalArray[0] = totalLine;


app.write_text_file_line_string_array(reportHandle,totalArray,1);
app.terminate_application();
    //     // Выводим все реально прочитанные байты
    //     if (readDataSize > 0)
    //     {
    //         for (int i = 0; i < readDataSize; i++)
    //         {
    //             log("readData[%d] = 0x%02X", i, readData[i]);
    //         }
    //     }
    //     else
    //     {
    //         log("Данные не получены (readDataSize = 0)");
    //     }

    //     app.wait(100, "");
    //     app.terminate_application();

    //     if (pEntry->access_default_session == "R" && status == 0) {
    //     log("Таблица права: доступ R, чтение прошло успешно (status=0), документация совпадает с реальностью.");
    //         {

    //         }
    //     } else {
    //     log("Не совпадает: таблица говорит access=%s, а status=%d",
    //         pEntry->access_default_session.c_str(), status);
    // }

}


   




void first(){
    Default_ParsData();
// int udsHandle = -1;
// int  status;
// status = rtlUIDiagnostics.tsdiag_can_create(&udsHandle,CH1, 0, 15, 0x78B, 1, 0x7AB, 1, 0x78B, 1);
// log ("status = %d", status);
// app.wait(1000, "");
// u8 readData [0xFFF];
// int readDataSize  = 0xFFF;
// status = rtlUIDiag   nostics.tsdiag_can_read_data_by_identifier(udsHandle, 0xA80A, readData, &readDataSize);
// app.wait(100, "");
// app.terminate_application();
// //[1] CAN 0x78B   
// TCAN f0 = {0,0x1,8,0,0x78B,2999235,{0x3, 0x22, 0xA8, 0xA, 0xAA, 0xAA, 0xAA, 0xAA}};
// com.transmit_can_async(&f0);
// app.wait(0, "");

// --- Записываем новое значение ---
// u8 writeData[1] = {0x02};
// int writeDataSize = 1;
// status = rtlUIDiagnostics.tsdiag_can_write_data_by_identifier(udsHandle, 0xA80A, writeData, writeDataSize);
// log("WRITE status = %d (0 = успех, иначе - код ошибки)", status);

// app.wait(200, "");

// // --- Перечитываем тот же DID, чтобы убедиться, что значение реально поменялось ---
// u8 readData[0xFFF];
// int readDataSize = 0xFFF;
// status = rtlUIDiagnostics.tsdiag_can_read_data_by_identifier(udsHandle, 0xA80A, readData, &readDataSize);
// log("READ status = %d, size = %d", status, readDataSize);

// if (readDataSize > 0) {
//     log("Прочитанное значение после записи: 0x%02X (ожидали 0x02)", readData[0]);
//     if (readData[0] == writeData[0]) {
//         log("УСПЕХ: значение реально изменилось на ECU!");
//     } else {
//         log("ВНИМАНИЕ: значение НЕ совпадает с тем, что записывали (запись могла не примениться)");
//     }
// }
app.wait(100, "");
app.terminate_application();
}





// void first()
// {
//     log("=== first() started ===");

//     // Загружаем таблицу DID
//     std::vector<DidRefEntry> didTable = loadDidTable();

//     if (didTable.empty())
//     {
//         log("ОШИБКА: Не удалось загрузить таблицу DID!");
//         app.terminate_application();
//         return;
//     }

//     log("Успешно загружено %zu DID", didTable.size());

//     // Поиск конкретного DID
//     unsigned short targetDID = 0xA80A;
//     const DidRefEntry* pEntry = findDid(didTable, targetDID);

//     if (pEntry)
//     {
//         log("DID 0x%04X найден в таблице!", pEntry->did);
//         log("Mnemonic: %s", pEntry->mnemonic.c_str());
//         log("Description: %s", pEntry->description.c_str());
//     }
//     else
//     {
//         log("DID 0x%04X НЕ найден!", targetDID);
//     }

//     // UDS часть
//     int udsHandle = -1;
//     int status = rtlUIDiagnostics.tsdiag_can_create(&udsHandle, CH1, 0, 15, 0x78B, 1, 0x7AB, 1, 0x78B, 1);
//     log("tsdiag_can_create status = %d", status);

//     app.wait(1000, "");

//     u8 readData[0xFFF] = {0};
//     int readDataSize = 0xFFF;

//     status = rtlUIDiagnostics.tsdiag_can_read_data_by_identifier(udsHandle, targetDID, readData, &readDataSize);
//     log("READ status = %d, size = %d", status, readDataSize);

//     app.wait(100, "");
//     app.terminate_application();
// }
// // void Excel_unpack()
// {

//     char *common_path;
//     const char* filename = "RBKE_REF.xlsx";
//     app.get_configuration_file_path(&common_path);// корень пути 
//     std::string path_to_data = std::string(common_path) + R"(TestData\)" + filename;//DUT\моя папка + имя cvs
//     log("Путь к тестовому набору данных: %s", path_to_data.c_str());
//     void* excelFile = nullptr;
//     int columnCount, rowCount, sheetNumber  =0 ; //тут сами указываем
//     log("=== Начало загрузки %s ===", filename);

//     if (app.excel_load(path_to_data.c_str(), &excelFile) != 0)
//     {
//         log("ОШИБКА: Не удалось загрузить файл");
//         return;
//     }



//     log("Файл загружен");
// }


//НАЧАЛО ПАРСИНГА ДАННЫХ




//{
// [1] CAN 0x78B   
//TCAN f0 = {0,0x1,8,0,0x78B,2999235,{0x3, 0x22, 0xA8, 0xA, 0xAA, 0xAA, 0xAA, 0xAA}};
//com.transmit_can_async(&f0);
//app.wait(0, "");
//}














// #include "DidRefC.h"
// void first(){

// int udsHandle = -1;
// int  status;
// status = rtlUIDiagnostics.tsdiag_can_create(&udsHandle,CH1, 0, 15, 0x78B, 1, 0x7AB, 1, 0x78B, 1);
// log ("status = %d", status);
// app.wait(1000, "");
// u8 readData [0xFFF];
// int readDataSize  = 0xFFF;
// status = rtlUIDiagnostics.tsdiag_can_read_data_by_identifier(udsHandle, 0xA80A, readData, &readDataSize);
// app.wait(100, "");
// app.terminate_application();
// }

// // [1] CAN 0x78B   
// //TCAN f0 = {0,0x1,8,0,0x78B,2999235,{0x3, 0x22, 0xA8, 0xA, 0xAA, 0xAA, 0xAA, 0xAA}};
// //com.transmit_can_async(&f0);
// //app.wait(0, "");

// void DID_default_sesson(){
    
//     // можно ли прочитать дид из default session
//     // можно ли редактировать did из default
//     //  >> провека в расширенной сессии можно ли R/W, 
//     // даже если нет то проводим тетс дальше и пробуем записать 
//     // ответ сравниавать с трассы по байтам( ответ можно склеить с строку где нужно 
//     // искать код ошибки 7F or 11)
    
    
// }
