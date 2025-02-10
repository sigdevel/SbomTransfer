# handlers/nuget_handler.py

import pandas as pd

def handle_nuget_purl(purl, component_name=None, version=None):
    if pd.isna(purl) and component_name and version:
        return f"pkg:nuget/{component_name}@{version}"
    
    try:
        _, _, nuget_part = purl.partition("pkg:nuget/")
        name, _, version = nuget_part.partition("@")
        if name and version:
            return f"pkg:nuget/{name}@{version}"
    except Exception:
        return None

def nuget_url_to_purl(url):
    try:
        parsed_url = url.split('/')
        if len(parsed_url) >= 5:
            name = parsed_url[-2]
            version = parsed_url[-1]
            return f"pkg:nuget/{name}@{version}"
    except Exception:
        return None

def generate_nuget_external_reference(component_name, version):
    if component_name and version:
        return f"https://www.nuget.org/packages/{component_name}/{version}"
    return None

