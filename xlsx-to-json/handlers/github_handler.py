# handlers/github_handler.py

from urllib.parse import urlparse

def handle_github_purl(purl):
    try:
        parsed_url = urlparse(purl)
        path_parts = parsed_url.path.strip('/').split('/')
        if len(path_parts) >= 2:
            repo_owner, repo_name = path_parts[:2]
            return f"pkg:github/{repo_owner}/{repo_name}"
    except Exception:
        return None

