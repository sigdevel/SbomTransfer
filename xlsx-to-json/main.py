# xlsx-to-json/main.py

import argparse
import json
import pandas as pd
import os
import requests
import subprocess
from uuid import uuid4
from datetime import datetime
from urllib.parse import urlparse

from handlers.github_handler import handle_github_purl
from handlers.nuget_handler import handle_nuget_purl, nuget_url_to_purl, generate_nuget_external_reference
from handlers.npm_handler import handle_npm_purl, npm_purl_to_website
from handlers.generic_handler import convert_generic_purl


def parse_arguments():
    parser = argparse.ArgumentParser(description="Генерация SBOM файла из Excel таблицы")
    parser.add_argument("-i", "--input", required=True, help="Путь к входному Excel-файлу (например, bom.xlsx)")
    return parser.parse_args()


def read_input_file(file_path):
    try:
        return pd.read_excel(file_path)
    except FileNotFoundError:
        print(f"Ошибка: Файл '{file_path}' не найден.")
        exit(1)
    except Exception as e:
        print(f"Ошибка при чтении Excel файла: {e}")
        exit(1)


def check_required_columns(df, required_columns):
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        print(f"Ошибка: В Excel файле отсутствуют обязательные столбцы: {', '.join(missing_columns)}")
        exit(1)


def convert_purl(purl, component_name=None, version=None):
    if pd.isna(purl) and component_name and version:
        return handle_nuget_purl(purl, component_name, version)

    if purl.startswith("pkg:nuget/"):
        return handle_nuget_purl(purl)

    if purl.startswith("pkg:npm/"):
        return handle_npm_purl(purl)

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

    generic_purl = convert_generic_purl(purl)
    if generic_purl:
        return generic_purl

    return None


def compute_hash(file_path):
    try:
        result = subprocess.run(
            ["/home/user/utils/CSP/cpverify", "-mk", "-alg", "GR3411", file_path],
            capture_output=True, text=True, check=True
        )
        hash_value = result.stdout.strip().splitlines()[-1]
        return hash_value.upper()
    except subprocess.CalledProcessError as e:
        print(f"Ошибка при расчете хэша для {file_path}: {e.stderr}")
        return None


def download_file(url):
    local_filename = f"/tmp/{uuid4()}.tgz"
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


def process_external_references(row, component_name, version):
    external_references = []
    unique_urls = set()

    if pd.notna(row["externalReferences"]):
        for ref in str(row["externalReferences"]).split(","):
            ref = ref.strip()
            if ref.endswith(".tgz") or ref.endswith(".tar.gz"):
                file_path = download_file(ref)
                if file_path:
                    hash_value = compute_hash(file_path)
                    os.remove(file_path)
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
                if ref not in unique_urls:
                    external_references.append({
                        "type": "website",
                        "url": ref
                    })
                    unique_urls.add(ref)
                if ref.startswith("https://github.com/"):
                    vcs_url = handle_github_purl(ref)
                elif ref.startswith("https://www.nuget.org/packages/"):
                    vcs_url = nuget_url_to_purl(ref)
                else:
                    vcs_url = ref
                external_references.append({
                    "type": "vcs",
                    "url": vcs_url
                })
    else:
        nuget_external_reference = generate_nuget_external_reference(component_name, version)
        if nuget_external_reference and nuget_external_reference not in unique_urls:
            external_references.append({
                "type": "website",
                "url": nuget_external_reference
            })
            unique_urls.add(nuget_external_reference)
            external_references.append({
                "type": "vcs",
                "url": handle_nuget_purl(None, component_name, version)
            })

    return external_references


def create_sbom_components(df):
    components = []
    dependencies = []

    for _, row in df.iterrows():
        bom_ref = row["BOM Reference"] if pd.notna(row["BOM Reference"]) else str(uuid4())
        component_name = row["Component"]
        version = row["Version"]

        attack_surface = row["attack_surface"] if row["attack_surface"] in ["yes", "no"] else "undefined"
        security_function = row["security_function"] if row["security_function"] in ["yes", "no"] else "undefined"

        component = {
            "type": row["Type"] if pd.notna(row["Type"]) else "library",
            "bom-ref": bom_ref,
            "name": component_name,
            "version": str(version) if pd.notna(version) else "",
            "purl": convert_purl(row["PURL"], component_name, version),
            "properties": [
                {
                    "name": "GOST:attack_surface",
                    "value": attack_surface
                },
                {
                    "name": "GOST:security_function",
                    "value": security_function
                }
            ]
        }

        external_references = process_external_references(row, component_name, version)

        # Проверка наличия ссылок на GitHub в type "distribution" и установка pkg:github, если найдена
        github_distribution = any(
            ref.get("type") == "distribution" and ref.get("url", "").startswith("https://github.com/")
            for ref in external_references
        )
        if github_distribution:
            component["purl"] = f"pkg:github/{component_name}@{version}"
        else:
            # Если purl был установлен ранее, оставить как есть
            if not component["purl"]:
                component["purl"] = convert_purl(row["PURL"], component_name, version)

        purl_value = component.get("purl", "")
        if purl_value and purl_value.startswith("pkg:npm/"):
            found_npm_website = any(
                ref.get("type") == "website" and "npmjs.com/package" in ref.get("url", "")
                for ref in external_references
            )
            if not found_npm_website:
                npm_website = npm_purl_to_website(component["purl"])
                if npm_website:
                    external_references.insert(0, {
                        "type": "website",
                        "url": npm_website
                    })

        if attack_surface == "undefined" or security_function == "undefined":
            nuget_external_reference = generate_nuget_external_reference(component_name, version)
            if nuget_external_reference and nuget_external_reference not in {ref['url'] for ref in external_references}:
                external_references.append({
                    "type": "website",
                    "url": nuget_external_reference
                })

        vcs_purl = None
        for ref in external_references:
            if ref.get("type") == "vcs":
                vcs_purl = ref.get("url")
                break
        if vcs_purl and component.get("purl") != vcs_purl:
            component["purl"] = vcs_purl

        if external_references:
            component["externalReferences"] = external_references

        components.append(component)
        dependencies.append({
            "ref": bom_ref,
            "dependsOn": []
        })

    return components, dependencies


def generate_sbom(components, dependencies):
    return {
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


def save_sbom_to_file(sbom_data, output_file):
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(sbom_data, f, indent=4, ensure_ascii=False)
        print(f"SBOM файл успешно сохранен: {output_file}")
    except Exception as e:
        print(f"Ошибка при записи SBOM файла: {e}")
        exit(1)


def main():
    args = parse_arguments()
    df = read_input_file(args.input)

    check_required_columns(df, ["Component", "Version", "Type", "BOM Reference", "PURL", "attack_surface", "security_function", "externalReferences"])

    components, dependencies = create_sbom_components(df)
    sbom_data = generate_sbom(components, dependencies)

    output_file = os.path.splitext(args.input)[0] + ".json"
    save_sbom_to_file(sbom_data, output_file)


if __name__ == "__main__":
    main()
