import importlib.util
import math
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xlsx-to-json"))


def _pandas_stub_isna(value):
    if value is None:
        return True
    try:
        return value != value
    except Exception:
        return False


pandas_stub = types.SimpleNamespace(
    isna=_pandas_stub_isna,
    read_excel=lambda *args, **kwargs: (_ for _ in ()).throw(
        ImportError("pandas is not available in the test environment")
    ),
)

sys.modules.setdefault("pandas", pandas_stub)


def load_module(module_path, module_name):
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


xlsx_main = load_module(ROOT / "xlsx-to-json" / "main.py", "xlsx_to_json_main")
generic_handler = load_module(
    ROOT / "xlsx-to-json" / "handlers" / "generic_handler.py",
    "generic_handler_module",
)


def test_convert_purl_strips_whitespace():
    assert xlsx_main.convert_purl("  pkg:npm/test@1.0  ") == "pkg:npm/test@1.0"


def test_convert_purl_non_string_falls_back_to_nuget():
    assert xlsx_main.convert_purl(12345, "Sample", "1.2.3") == "pkg:nuget/Sample@1.2.3"


def test_convert_purl_returns_none_for_missing_metadata():
    assert xlsx_main.convert_purl(None) is None


def test_convert_generic_from_archive_url():
    archive_url = "https://example.com/downloads/pkg-lib-2.0.tar.gz"
    assert generic_handler.convert_generic_purl(archive_url) == "pkg:generic/pkg-lib@2.0"


def test_convert_generic_ignores_empty_input():
    assert generic_handler.convert_generic_purl("   ") is None
