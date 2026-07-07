#include "DidRefC.h"
// std::vector<RoutPath> getRoutPath(Test &Report, std::string RT_name)

    // {
    //     char *common_path;
    //     void *file_xls;
    //     int rowCount, columnCount, sheetNumber = 0;
    //     Report.TestFunctionStart("Поиск пути к таблице : %s", RT_name.c_str());
    //     {

    //         app.get_configuration_file_path(&common_path);// корень пути 
    //         std::string path_to_RT = std::string(common_path) + R"(DUT\TestData\)" + RT_name;//DUT\моя папка + имя cvs
    //         // Report.TestStep("Путь к исходной таблице с тестовым набором сообщений: %s", path_to_RT.c_str());
    //         log("Путь к исходной таблице с тестовым набором сообщений: %s", path_to_RT.c_str());
    //         if (app.excel_load(path_to_RT.c_str(), &file_xls))//тут можно целиком путь захаркодить в случае проблем 
    //         {
    //             Report.TestStepFail("Ошибка загрузки таблицы");
    //             return {};
    //         }
    //         if (app.excel_get_cell_count(file_xls, sheetNumber, &rowCount, &columnCount))
    //         {
    //             return {};
    //         }
    //         else
    //         {
    //             Report.TestStepPass("Таблица загружена");
    //         }
    //     }
    //     Report.TestFunctionEnd();
    //     std::vector<RoutPath> RoutPathList;
    //     std::unordered_set<u16> uniqueIDs;
    //     Report.TestFunctionStart("Обработка исходной таблицы с тестовым набором сообщений");
    // }



void first()
{
    log("=== first() started ===");

    // Загружаем таблицу DID
    std::vector<DidRefEntry> didTable = loadDidTable();

    if (didTable.empty())
    {
        log("ОШИБКА: Не удалось загрузить таблицу DID!");
        app.terminate_application();
        return;
    }

    log("Успешно загружено %zu DID", didTable.size());

    // Поиск конкретного DID
    unsigned short targetDID = 0xA80A;
    const DidRefEntry* pEntry = findDid(didTable, targetDID);

    if (pEntry)
    {
        log("DID 0x%04X найден в таблице!", pEntry->did);
        log("Mnemonic: %s", pEntry->mnemonic.c_str());
        log("Description: %s", pEntry->description.c_str());
    }
    else
    {
        log("DID 0x%04X НЕ найден!", targetDID);
    }

    // UDS часть
    int udsHandle = -1;
    int status = rtlUIDiagnostics.tsdiag_can_create(&udsHandle, CH1, 0, 15, 0x78B, 1, 0x7AB, 1, 0x78B, 1);
    log("tsdiag_can_create status = %d", status);

    app.wait(1000, "");

    u8 readData[0xFFF] = {0};
    int readDataSize = 0xFFF;

    status = rtlUIDiagnostics.tsdiag_can_read_data_by_identifier(udsHandle, targetDID, readData, &readDataSize);
    log("READ status = %d, size = %d", status, readDataSize);

    app.wait(100, "");
    app.terminate_application();
}
// void Excel_unpack()
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
void ParsData
{
    
}



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