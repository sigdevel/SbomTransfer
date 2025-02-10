# json-to-xlsx/main.py

import argparse
import json
import pandas as pd
import os

parser = argparse.ArgumentParser(description="Обработка BOM файла и экспорт данных компонентов в Excel")
parser.add_argument("-i", "--input", required=True, help="Путь к входному JSON-файлу (например, bom.json)")

args = parser.parse_args()

# чтение входного файла
input_file = args.input
try:
    with open(input_file, 'r', encoding='utf-8') as f:
        json_data = json.load(f)
except FileNotFoundError:
    print(f"Ошибка: Файл '{input_file}' не найден.")
    exit(1)
except json.JSONDecodeError:
    print(f"Ошибка: Файл '{input_file}' не является корректным JSON")
    exit(1)

# генерируем имя выходного файла
base_name = os.path.splitext(os.path.basename(input_file))[0]
output_file = f"{base_name}.xlsx"

# извлечение данных компонентов
components_data = []
for component in json_data.get("components", []):
    name = component.get("name", "Не указано")
    version = component.get("version", "Не указано")
    comp_type = component.get("type", "Не указано")
    bom_ref = component.get("bom-ref", "Не указано")
    purl = component.get("purl", "Не указано")

    # извлечение данных externalReferences, удаляя дубликаты и оставляя только type="website"
    external_references = list({
        ref.get("url", "Не указано")
        for ref in component.get("externalReferences", [])
        if ref.get("type") == "website"
    })
    external_references_str = ", ".join(external_references)

    # извлечение данных из properties
    attack_surface = "Не указано"
    security_function = "Не указано"
    for prop in component.get("properties", []):
        if prop.get("name") == "GOST:attack_surface":
            attack_surface = prop.get("value", "Не указано")
        elif prop.get("name") == "GOST:security_function":
            security_function = prop.get("value", "Не указано")

    components_data.append({
        "Component": name,
        "Version": version,
        "Type": comp_type,
        "BOM Reference": bom_ref,
        "PURL": purl,
        "externalReferences": external_references_str,
        "attack_surface": attack_surface,
        "security_function": security_function
    })

# экспорт в Excel
df = pd.DataFrame(components_data)
df.to_excel(output_file, index=False)
print(f"Данные сохранены в файл: {output_file}")

