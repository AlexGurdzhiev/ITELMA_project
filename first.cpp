#include "first.h"
void first(){

int udsHandle = -1;
int  status;
status = rtlUIDiagnostics.tsdiag_can_create(&udsHandle,CH1, 0, 15, 0x78B, 1, 0x7AB, 1, 0x78B, 1);
log ("status = %d", status);
app.wait(1000, "");
u8 readData [0xFFF];
int readDataSize  = 0xFFF;
status = rtlUIDiagnostics.tsdiag_can_read_data_by_identifier(udsHandle, 0xA80A, readData, &readDataSize);
app.wait(100, "");
app.terminate_application();
}