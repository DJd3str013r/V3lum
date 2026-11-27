"""P172 cond 12: precision and recall of the extraction engine on a corpus of CTI report prose,
a phishing e-mail, a PT-BR SMS/WhatsApp scam text (personal data replaced) and analyst notes,
against hand-written expected entity lists (tests/fixtures/ioc_corpus/expected.json)."""

from __future__ import annotations

import json

import pytest

from tests.fakes import FIXTURES
from v3lum.core import ioc

CORPUS = FIXTURES / "ioc_corpus"
EXPECTED = json.loads((CORPUS / "expected.json").read_text(encoding="utf-8"))
FILES = sorted(k for k in EXPECTED if not k.startswith("_"))
PRECISION_MIN = 0.95
RECALL_MIN = 0.90


def found_keys(name: str) -> set[str]:
    """What an analyst is shown: every entity except file-name lookalikes (low_confidence_tld)."""
    result = ioc.extract((CORPUS / name).read_text(encoding="utf-8"))
    return {i.entity.key for i in result.entities if "low_confidence_tld" not in i.flags}


def matches(key: str, pattern: str) -> bool:
    return key.startswith(pattern[:-1]) if pattern.endswith("*") else key == pattern


def test_corpus_files_are_trimmed_and_listed():
    on_disk = sorted(p.name for p in CORPUS.iterdir() if p.suffix != ".md" and p.name != "expected.json")
    assert on_disk == FILES
    for name in FILES:
        assert (CORPUS / name).stat().st_size < 4096


@pytest.mark.parametrize("name", FILES)
def test_forbidden_values_never_come_out(name):
    found = found_keys(name)
    for key in EXPECTED[name]["forbidden"]:
        assert key not in found, f"{name}: {key}"
    assert not any(k.startswith("cpf:") for k in found)


@pytest.mark.parametrize("name", FILES)
def test_per_file_quality(name):
    found = found_keys(name)
    expected = EXPECTED[name]["expected"]
    false_pos = sorted(k for k in found if not any(matches(k, p) for p in expected))
    missed = sorted(p for p in expected if not any(matches(k, p) for k in found))
    precision = (len(found) - len(false_pos)) / max(1, len(found))
    recall = (len(expected) - len(missed)) / max(1, len(expected))
    assert precision >= 0.9, f"{name}: precision {precision:.2f}, unexpected {false_pos}"
    assert recall >= 0.85, f"{name}: recall {recall:.2f}, missed {missed}"


def test_corpus_precision_and_recall():
    tp = extracted = expected = 0
    for name in FILES:
        found = found_keys(name)
        patterns = EXPECTED[name]["expected"]
        tp += sum(1 for k in found if any(matches(k, p) for p in patterns))
        extracted += len(found)
        expected += len(patterns)
    precision, recall = tp / extracted, min(1.0, tp / expected)
    assert precision >= PRECISION_MIN, f"precision {precision:.3f}"
    assert recall >= RECALL_MIN, f"recall {recall:.3f}"


def test_personal_data_in_the_scam_text_is_protected():
    result = ioc.extract((CORPUS / "ptbr_sms_whatsapp.txt").read_text(encoding="utf-8"))
    assert result.masked["cpf"] == {"count": 1, "previews": ["***.444.777-**"]}
    blob = json.dumps(result.to_dict(), ensure_ascii=False)
    assert "111.444.777-35" not in blob and "4111 1111 1111 1111" not in blob
    personal = [i for i in result.entities if "personal" in i.flags]
    assert personal and all(not i.expand for i in personal)
