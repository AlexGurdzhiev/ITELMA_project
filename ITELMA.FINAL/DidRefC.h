#ifndef DIDREFC_H
#define DIDREFC_H




#include <vector>
#include <string>
#include <cstdlib>
#include <cstring>

// Порядок столбцов в RBKE_REF.xlsx (0-based, как использует app.excel_get_cell_value)
enum RbkeColumn {
    COL_DID = 0,
    COL_MNEMONIC,
    COL_DESCRIPTION,
    COL_SIZE_BITS,
    COL_BYTE_START,
    COL_LENGTH_BYTES,
    COL_BIT_OFFSET,
    COL_DATA_TYPE,
    COL_SIGNED,
    COL_UNIT,
    COL_RESOLUTION,
    COL_VALUE_MIN,
    COL_VALUE_MAX,
    COL_CODING,
    COL_DEFAULT_VALUE,
    COL_ACCESS_DEFAULT,
    COL_ACCESS_EXTENDED
};

struct DidRefEntry {
    unsigned short did = 0;
    std::string mnemonic;
    std::string description;
    int size_bits = 0;
    int byte_start = 0;
    int length_bytes = 0;
    int bit_offset = 0;
    std::string data_type;
    std::string sign;
    std::string unit;
    double resolution = 0;
    double value_min = 0;
    double value_max = 0;
    std::string coding;
    std::string default_value;
    std::string access_default_session;
    std::string access_extended_session;
};

std::vector<DidRefEntry> loadDidTable() {
    std::vector<DidRefEntry> result;
    // char* common_path;
    // void* file_xls;
    // int rowCount, columnCount;// поменять названия 
    int n = 2;// количесво страниц 



    char *common_path;
    const char* filename = "RBKE_REF.xlsx";
    app.get_configuration_file_path(&common_path);// корень пути 
    std::string path_to_data = std::string(common_path) + R"(TestData\)" + filename;//DUT\моя папка + имя cvs
    log("Путь к тестовому набору данных: %s", path_to_data.c_str());
    void* excelFile = nullptr;
    int columnCount, rowCount, sheetNumber  =0 ; //тут сами указываем
    log("=== Начало загрузки %s ===", filename);

    if (app.excel_load(path_to_data.c_str(), &excelFile) != 0)
    {
        log("ОШИБКА: Не удалось загрузить файл");
        return{};
    }



    log("Файл загружен");
    // app.get_configuration_file_path(&common_path);
    // std::string path = std::string(common_path) + R"(DUT\TestData\)" + "RBKE_REF.xlsx";
    // log("Путь к таблице DID: %s", path.c_str()); // переписать под правильный путь

    // if (app.excel_load(path.c_str(), &excelFile)) {
    //     log("Ошибка загрузки RBKE_REF.xlsx");
    //     return result;
    // }

    // Лист 0 = DID_REF, лист 1 = DID_S50 (проверено: нумерация листов с 0)
    for (int sheetNumber = 0; sheetNumber < n; ++sheetNumber) {
        if (app.excel_get_cell_count(excelFile, sheetNumber, &rowCount, &columnCount)) {
            log("Не удалось получить размер листа %d", sheetNumber);
            continue;
        }
        log("Лист %d: rowCount=%d columnCount=%d", sheetNumber, rowCount, columnCount);

        char* raw = nullptr;
        // row_index = 0 - заголовок, пропускаем. Дальше данные и пустые строки чередуются -
        // поэтому не считаем через один, а просто пропускаем строки с пустым DID.
        for (int row = 1; row < rowCount; ++row) {
            app.excel_get_cell_value(excelFile, sheetNumber, row, COL_DID, &raw);
            if (raw == nullptr || raw[0] == '\0') continue; // пустая строка-разделитель или конец таблицы
            
            DidRefEntry e;
            std::string didStr(raw);
            const char* didHexPart = (didStr[0] == '$') ? didStr.c_str() + 1 : didStr.c_str();
            e.did = (unsigned short)strtoul(didHexPart, nullptr, 16);

            app.excel_get_cell_value(excelFile, sheetNumber, row, COL_MNEMONIC, &raw);
            e.mnemonic = raw ? raw : "";

            app.excel_get_cell_value(excelFile, sheetNumber, row, COL_DESCRIPTION, &raw);
            e.description = raw ? raw : "";

            app.excel_get_cell_value(excelFile, sheetNumber, row, COL_SIZE_BITS, &raw);
            e.size_bits = (raw && raw[0]) ? atoi(raw) : 0;

            app.excel_get_cell_value(excelFile, sheetNumber, row, COL_BYTE_START, &raw);
            e.byte_start = (raw && raw[0]) ? atoi(raw) : 0;

            app.excel_get_cell_value(excelFile, sheetNumber, row, COL_LENGTH_BYTES, &raw);
            e.length_bytes = (raw && raw[0]) ? atoi(raw) : 0;

            app.excel_get_cell_value(excelFile, sheetNumber, row, COL_BIT_OFFSET, &raw);
            e.bit_offset = (raw && raw[0]) ? atoi(raw) : 0;

            app.excel_get_cell_value(excelFile, sheetNumber, row, COL_DATA_TYPE, &raw);
            e.data_type = raw ? raw : "";

            app.excel_get_cell_value(excelFile, sheetNumber, row, COL_SIGNED, &raw);
            e.sign = raw ? raw : "";

            app.excel_get_cell_value(excelFile, sheetNumber, row, COL_UNIT, &raw);
            e.unit = raw ? raw : "";

            app.excel_get_cell_value(excelFile, sheetNumber, row, COL_RESOLUTION, &raw);
            e.resolution = (raw && raw[0]) ? atof(raw) : 0.0;

            app.excel_get_cell_value(excelFile, sheetNumber, row, COL_VALUE_MIN, &raw);
            e.value_min = (raw && raw[0]) ? atof(raw) : 0.0;

            app.excel_get_cell_value(excelFile, sheetNumber, row, COL_VALUE_MAX, &raw);
            e.value_max = (raw && raw[0]) ? atof(raw) : 0.0;

            app.excel_get_cell_value(excelFile, sheetNumber, row, COL_CODING, &raw);
            e.coding = raw ? raw : "";

            app.excel_get_cell_value(excelFile, sheetNumber, row, COL_DEFAULT_VALUE, &raw);
            e.default_value = raw ? raw : "";

            app.excel_get_cell_value(excelFile, sheetNumber, row, COL_ACCESS_DEFAULT, &raw);
            e.access_default_session = raw ? raw : "";

            app.excel_get_cell_value(excelFile, sheetNumber, row, COL_ACCESS_EXTENDED, &raw);
            e.access_extended_session = raw ? raw : "";

            result.push_back(e);
        }
    }

    app.excel_unload_all();
    log("Всего загружено DID: %zu", result.size());
    return result;
}

// Поиск записи по коду DID (например 0xA80A)
const DidRefEntry* findDid(const std::vector<DidRefEntry>& table, unsigned short did) {
    for (const auto& e : table) 
    {
        if (e.did == did) return &e;
    }
    return nullptr;
}


#endif // DIDREFC_H



// file_xls - был переименован в excelFile
