# handlers/npm_handler.py

def handle_npm_purl(purl):
    try:
        _, _, npm_part = purl.partition("pkg:npm/")
        name, _, version = npm_part.partition("@")
        if name and version:
            return f"pkg:npm/{name}@{version}"
    except Exception:
        return None

def npm_purl_to_website(purl):
    try:
        npm_part = purl[len("pkg:npm/"):]
        if "@" in npm_part:
            name_part, _ = npm_part.rsplit("@", 1)
        else:
            name_part = npm_part
        if name_part.startswith("%40"):
            parts = name_part.split('/')
            if len(parts) == 2:
                website_name = parts[1]
            else:
                website_name = name_part
        elif name_part.startswith("@"):
            parts = name_part.split('/')
            if len(parts) == 2:
                website_name = parts[1]
            else:
                website_name = name_part
        else:
            website_name = name_part
        return f"https://www.npmjs.com/package/{website_name}"
    except Exception:
        return None

