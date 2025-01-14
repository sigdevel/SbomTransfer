import argparse
import json
import pandas as pd
import os
import requests
import subprocess
from uuid import uuid4
from datetime import datetime
from urllib.parse import urlparse
import tarfile

parser = argparse.ArgumentParser(description="Генерация SBOM файла из Excel таблицы")
parser.add_argument("-i", "--input", required=True, help="Путь к входному Excel-файлу (например, bom.xlsx)")

args = parser.parse_args()


input_file = args.input
output_file = os.path.splitext(input_file)[0] + ".json"  # выходной файл с тем же именем, но расширением .json

try:
    df = pd.read_excel(input_file)
except FileNotFoundError:
    print(f"Ошибка: Файл '{input_file}' не найден.")
    exit(1)
except Exception as e:
    print(f"Ошибка при чтении Excel файла: {e}")
    exit(1)

# проверка структуры входного файла
required_columns = ["Component", "Version", "Type", "BOM Reference", "PURL", "attack_surface", "security_function", "externalReferences"]
missing_columns = [col for col in required_columns if col not in df.columns]

if missing_columns:
    print(f"Ошибка: В Excel файле отсутствуют обязательные столбцы: {', '.join(missing_columns)}")
    exit(1)

def convert_generic_purl(purl):
    if pd.isna(purl):
        return None

    if purl.startswith("https://github.com/") and "archive" in purl:
        try:
            _, _, path_part = purl.partition("https://github.com/")
            repo_and_path, _, version_part = path_part.partition("/archive/")
            if repo_and_path and version_part:
                version = version_part.replace('.tar.gz', '').replace('.zip', '')
                return f"pkg:github/{repo_and_path}@{version}"
        except Exception:
            return None

    if any(ext in purl for ext in ['tar.gz', 'tar.xz', 'zip']):
        try:
            parsed_url = urlparse(purl)
            path_parts = parsed_url.path.strip('/').split('/')
            if path_parts:
                name_version = path_parts[-1]
                name_version = name_version.replace('.tar.gz', '').replace('.tar.xz', '').replace('.zip', '')
                name, version = name_version.rsplit('-', 1)
                return f"pkg:generic/{name}@{version}"
        except Exception:
            return None

    return None

def convert_purl(purl):
    if pd.isna(purl):
        return None

    if purl.startswith("pkg:nuget/"):
        try:
            _, _, nuget_part = purl.partition("pkg:nuget/")
            name, _, version = nuget_part.partition("@")
            if name and version:
                return f"pkg:nuget/{name}@{version}"
        except Exception:
            return None

    if purl.startswith("pkg:npm/"):
        try:
            _, _, npm_part = purl.partition("pkg:npm/")
            name, _, version = npm_part.partition("@")
            if name and version:
                return f"pkg:npm/{name}@{version}"
        except Exception:
            return None

    if purl.startswith("pkg:maven/"):
        try:
            _, _, maven_part = purl.partition("pkg:maven/")
            group_and_artifact, _, version = maven_part.partition("@")
            if group_and_artifact and version:
                group, _, artifact = group_and_artifact.rpartition("/")
                if group and artifact:
                    return f"pkg:maven/{group}/{artifact}@{version}"
        except Exception:
            return None

    # используем общую функцию для обработки generic пакетов
    generic_purl = convert_generic_purl(purl)
    if generic_purl:
        return generic_purl

    return None

 # функция для вычисления хэша через cpverify
def compute_hash(file_path):
    try:
        # запуск утилиты и захват результата
        result = subprocess.run(
            ["/home/user/utils/CSP/cpverify", "-mk", "-alg", "GR3411", file_path],
            capture_output=True, text=True, check=True
        )
        hash_value = result.stdout.strip().splitlines()[-1]  # последняя строка - это хэш
        return hash_value.upper()
    except subprocess.CalledProcessError as e:
        print(f"Ошибка при расчете хэша для {file_path}: {e.stderr}")
        return None

#скачивание файла перед подсчетом
def download_file(url):
    local_filename = f"/tmp/{uuid4()}.tgz"  #сохранение файла tmp
    try:
        with requests.get(url, stream=True) as response:
            response.raise_for_status()
            with open(local_filename, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
        return local_filename
    except Exception as e:
        print(f"Ошибка при скачивании файла {url}: {e}")
        return None

'''
# функция для извлечения и расчета хэша из tar.gz файла
def extract_and_compute_tar_hash(file_path):
    local_dir = f"/tmp/{uuid4()}"
    try:
        with tarfile.open(file_path, "r:gz") as tar:
            tar.extractall(path=local_dir)
        computed_hash = compute_hash(local_dir)
        subprocess.run(["rm", "-rf", local_dir])  # удаляем временную директорию после использования
        return computed_hash
    except Exception as e:
        print(f"Ошибка при обработке tar.gz файла {file_path}: {e}")
        return None
'''

# формирование SBOM
components = []
dependencies = []
for _, row in df.iterrows():
    bom_ref = row["BOM Reference"] if pd.notna(row["BOM Reference"]) else str(uuid4())
    component = {
        "type": row["Type"] if pd.notna(row["Type"]) else "library",
        "bom-ref": bom_ref,
        "name": row["Component"],
        "version": row["Version"],
        "purl": convert_purl(row["PURL"]),
        "properties": [
            {
                "name": "GOST:attack_surface",
                "value": row["attack_surface"] if pd.notna(row["attack_surface"]) else "no"
            },
            {
                "name": "GOST:security_function",
                "value": row["security_function"] if pd.notna(row["security_function"]) else "no"
            }
        ]
    }

    external_references = []
    if pd.notna(row["externalReferences"]):
        for ref in str(row["externalReferences"]).split(","):
            ref = ref.strip()
            if ref.endswith(".tgz") or ref.endswith(".tar.gz"):
                file_path = download_file(ref)
                if file_path:
                    hash_value = compute_hash(file_path)
                    #hash_value = extract_and_compute_tar_hash(file_path)
                    os.remove(file_path)  #удаляем временный файл
                    external_references.append({
                        "type": "distribution",
                        "url": ref
                    })
                    if hash_value:
                        external_references.append({
                            "type": "source-distribution",
                            "url": ref,
                            "hashes": [
                                {
                                    "alg": "STREEBOG-256",
                                    "content": hash_value
                                }
                            ]
                        })
            else:
                external_references.append({
                    "type": "website",
                    "url": ref
                })
                external_references.append({
                    "type": "vcs",
                    "url": ref
                })
    if external_references:
        component["externalReferences"] = external_references

    components.append(component)
    dependencies.append({
        "ref": bom_ref,
        "dependsOn": []
    })

sbom_data = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": f"urn:uuid:{uuid4()}",
    "version": 1,
    "metadata": {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tools": [
            {
                "vendor": "OWASP",
                "name": "Dependency-Track",
                "version": "4.12.0"
            }
        ],
        "component": {
            "type": "library",
            "bom-ref": str(uuid4()),
            "name": "_Test_cert",
            "version": "",
            "manufacturer": {
                "name": "_Test_org"
            }
        }
    },
    "components": components,
    "dependencies": dependencies
}

# запись данных в выходной SBOM JSON файл
try:
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(sbom_data, f, indent=4, ensure_ascii=False)
    print(f"SBOM файл успешно сохранен: {output_file}")
except Exception as e:
    print(f"Ошибка при записи SBOM файла: {e}")
    exit(1)

