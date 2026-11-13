"""Contract tests for the Streamlit URL Investigation integration.

These tests intentionally inspect the page's AST rather than importing the
Streamlit application, so CI does not need to launch a web server or access the
private local model artifact.
"""
from __future__ import annotations

import ast
from pathlib import Path


APP_PATH = Path(__file__).resolve().parents[1] / "app" / "main.py"


def _url_investigation_page() -> ast.If:
    tree = ast.parse(APP_PATH.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        test = node.test
        if (
            isinstance(test, ast.Compare)
            and isinstance(test.left, ast.Name)
            and test.left.id == "page"
            and any(
                isinstance(operator, ast.Eq)
                and isinstance(comparator, ast.Constant)
                and comparator.value == "URL Investigation"
                for operator, comparator in zip(test.ops, test.comparators)
            )
        ):
            return node
    raise AssertionError("URL Investigation page branch was not found.")


def test_url_investigation_calls_the_production_inference_api() -> None:
    page = _url_investigation_page()
    calls = {
        node.func.id
        for node in ast.walk(page)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "predict_url" in calls
    assert "load_phishx_model" in calls


def test_url_investigation_displays_model_and_security_outputs() -> None:
    page = _url_investigation_page()
    source = ast.unparse(page)
    for required_output in (
        "phishing_probability",
        "legitimate_probability",
        "contributions",
        "security_assessment",
        "actual_host",
        "extraction_warnings",
    ):
        assert required_output in source


def test_url_investigation_no_longer_uses_the_legacy_manual_signal_only_path() -> None:
    page = _url_investigation_page()
    source = ast.unparse(page)
    assert "extract_basic_signals" not in source
    assert "predict_url" in source
