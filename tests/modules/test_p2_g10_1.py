"""Batch p2-G10-1 checks across modules: the fixtures carry no personal data or keys (public companies,
public places and documentation values only) and the bundled data has its provenance."""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
DIRS = ["gleif", "cep_lookup", "cnae_tables", "portal_transparencia_api"]
ACCEPTANCE = [FIXTURES / "acceptance" / "cnpj" / "gleif.json", FIXTURES / "acceptance" / "cnpj" / "portal_transparencia_api.json"]
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
CPF_FULL = re.compile(r"(?<![\d*])\d{3}\.\d{3}\.\d{3}-\d{2}(?![\d])")
PHONE = re.compile(r"\+55\s?\d{2}\s?\d{4,5}-?\d{4}")
SECRET_HINTS = re.compile(r"(chave-api-dados\"?\s*:|authorization\"?\s*:|set-cookie|api[_-]?key=)", re.I)


def _texts() -> list[tuple[str, str]]:
    out = []
    files = [p for d in DIRS for p in sorted((FIXTURES / d).iterdir()) if p.is_file()] + ACCEPTANCE
    for path in files:
        text = path.read_text(encoding="utf-8")
        out.append((path.name, text))
        if path.suffix == ".json":
            try:
                doc = json.loads(text)
            except ValueError:
                continue
            if isinstance(doc, dict) and isinstance(doc.get("body_b64"), str):
                out.append((path.name + "#body", base64.b64decode(doc["body_b64"]).decode("latin-1")))
    return out


@pytest.mark.parametrize(("name", "text"), _texts())
def test_fixtures_carry_no_personal_data_or_keys(name, text):
    for domain in EMAIL.findall(text):
        assert domain.lower().endswith(("example.com", "example.org", "example.net")), (name, domain)
    assert not CPF_FULL.search(text), name
    for phone in PHONE.findall(text):
        assert re.search(r"5555-?01\d\d$", phone), (name, phone)
    assert not SECRET_HINTS.search(text), name
