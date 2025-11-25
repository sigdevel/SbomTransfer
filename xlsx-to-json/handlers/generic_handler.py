# handlers/generic_handler.py

import pandas as pd

from urllib.parse import urlparse

def convert_generic_purl(purl):
    if pd.isna(purl) or not isinstance(purl, str):
        return None

    purl = purl.strip()

    if not purl:
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

