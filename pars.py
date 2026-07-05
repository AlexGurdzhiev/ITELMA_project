import pandas as pd
import json

EXCEL_FILE = "RBKE_REF.xlsx"

df = pd.read_excel(EXCEL_FILE)

needed_columns = [
    "DID Code\n(Hexa.)",
    "Size (bit)",
    "Value min (offset) (Decimal)",
    "Value max (Decimal)",
    "$1001 Default Session",
    "$1003 Extended DiagSession"
]

# Проверка наличия столбцов
for col in needed_columns:
    if col not in df.columns:
        print(f"Не найден столбец: {col}")

df = df[needed_columns]

df.to_csv("did_selected_columns.csv", index=False)

records = []

for _, row in df.iterrows():

    records.append({
        "did": str(row["DID Code\n(Hexa.)"]).strip(),
        "size": row["Size (bit)"],
        "min": row["Value min (offset) (Decimal)"],
        "max": row["Value max (Decimal)"],
        "default": str(row["$1001 Default Session"]).strip(),
        "extended": str(row["$1003 Extended DiagSession"]).strip()
    })

with open("did_config.json","w",encoding="utf-8") as f:
    json.dump(records,f,indent=4)

print("Done")