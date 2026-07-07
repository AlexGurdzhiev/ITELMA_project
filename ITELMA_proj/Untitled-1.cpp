



std::vector<RoutPath> getRoutPath(Test &Report, std::string RT_name)
    {
        char *common_path;
        void *file_xls;
        int rowCount, columnCount, sheetNumber = 0;
        Report.TestFunctionStart("Поиск пути к таблице : %s", RT_name.c_str());
        {

            app.get_configuration_file_path(&common_path);// корень пути 
            std::string path_to_RT = std::string(common_path) + R"(DUT\TestData\)" + RT_name;//DUT\моя папка + имя cvs
            // Report.TestStep("Путь к исходной таблице с тестовым набором сообщений: %s", path_to_RT.c_str());
            log("Путь к исходной таблице с тестовым набором сообщений: %s", path_to_RT.c_str());
            if (app.excel_load(path_to_RT.c_str(), &file_xlsтут можно целиком путь захаркодить в случае проблем 
            {
                Report.TestStepFail("Ошибка загрузки таблицы");
                return {};
            }
            if (app.excel_get_cell_count(file_xls, sheetNumber, &rowCount, &columnCount))
            {
                return {};
            }
            else
            {
                Report.TestStepPass("Таблица загружена");
            }
        }
        Report.TestFunctionEnd();
        std::vector<RoutPath> RoutPathList;
        std::unordered_set<u16> uniqueIDs;
        Report.TestFunctionStart("Обработка исходной таблицы с тестовым набором сообщений");
        {
            char *raw_excel_data;
            for (auto row_index = 1; row_index <= rowCount - 1; ++row_index)
            {
                RoutPath path;
                // Проверка флага Enable в таблице
                app.excel_get_cell_value(file_xls, 0, row_index, ColumnIndex::Enable, &raw_excel_data);
                auto Enable_value = static_cast<int>(strtol(raw_excel_data, nullptr, 10));
                if (Enable_value != 1)
                {
                    continue;
                }
                app.excel_get_cell_value(file_xls, 0, row_index, ColumnIndex::ID, &raw_excel_data);
                path.ID = static_cast<int>(strtol(raw_excel_data, nullptr, 16));
                // Проверка на дубликаты ID
                if (uniqueIDs.find(path.ID) != uniqueIDs.end())
                {
                    log("!!! В таблице обнаружен дублирующийся ID 0x%04X в строке %d. Функция прервана!!!", path.ID, row_index);
                    Report.TestStepFail("!!! В таблице обнаружен дублирующийся ID 0x%04X в строке %d. Функция прервана!!!", path.ID, row_index);
                    app.excel_unload_all();
                    return {};
                }
                uniqueIDs.insert(path.ID);
                // Конец проверки

                app.excel_get_cell_value(file_xls, 0, row_index, ColumnIndex::Period, &raw_excel_data);
                path.Period = static_cast<int>(strtol(raw_excel_data, nullptr, 10));

                app.excel_get_cell_value(file_xls, 0, row_index, ColumnIndex::Event, &raw_excel_data);
                path.FlagEvent = (raw_excel_data[0] == 'x') ? 1 : 0;

                app.excel_get_cell_value(file_xls, 0, row_index, ColumnIndex::Periodic, &raw_excel_data);
                path.FlagPeriodic = (raw_excel_data[0] == 'x') ? 1 : 0;

                app.excel_get_cell_value(file_xls, 0, row_index, ColumnIndex::Diag, &raw_excel_data);
                path.FlagDiag = (raw_excel_data[0] == 'x') ? 1 : 0;

                app.excel_get_cell_value(file_xls, 0, row_index, ColumnIndex::WakeUp, &raw_excel_data);
                path.FlagWakeUp = (raw_excel_data[0] == 'x') ? 1 : 0;

                // обработка столбцов CAN1 - CAN6
                int CAN_COUNT = CH6;
                int CAN_START = ColumnIndex::CAN1;
                for (int offset = CH1; offset <= CAN_COUNT; offset++)
                {
                    app.excel_get_cell_value(file_xls, 0, row_index, CAN_START + offset, &raw_excel_data);
                    if (raw_excel_data[0] == '\0')
                    {
                        continue; // пустая ячейка
                    }
                    if (raw_excel_data[0] == 'R')
                    {
                        if (path.Source == 0x0F)
                        {path.Source = offset;
                        }
                        else
                        {
                            log("!!!В таблице маршрутизации продублированы каналы Source. Функция прервана!!!");
                            Report.TestStepFail("!!!В таблице маршрутизации продублированы каналы Source. Функция прервана!!!");
                            app.excel_unload_all();
                            return {};
                        }
                    }
                    else if (raw_excel_data[0] == 'T')
                    {
                        path.Destination[offset] = 1;
                    }
                }
                RoutPathList.push_back(path);
            }
            int DID_count = RoutPathList.size();
            if (DID_count == 0)
            {
                Report.TestStepWarning("Количество обработанных маршрутов = %lld", DID_count);
            }
            else
                Report.TestStepPass("Количество обработанных маршрутов = %lld", DID_count);
        }
        app.excel_unload_all();
        Report.TestFunctionEnd();
        return RoutPathList;
    }