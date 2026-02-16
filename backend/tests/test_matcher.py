"""Tests for app.services.matcher — extract_technique_ids and INDUSTRY_KEYWORDS."""

from __future__ import annotations

from app.services.matcher import INDUSTRY_KEYWORDS, extract_technique_ids


# ---------------------------------------------------------------------------
# extract_technique_ids
# ---------------------------------------------------------------------------


class TestExtractTechniqueIds:
    def test_single_technique(self) -> None:
        assert extract_technique_ids("Uses T1566 for phishing") == ["T1566"]

    def test_sub_technique(self) -> None:
        result = extract_technique_ids("T1566.001 spearphishing attachment")
        assert result == ["T1566.001"]

    def test_multiple_techniques(self) -> None:
        text = "Actor uses T1071 and T1059.001 for C2 and execution"
        result = extract_technique_ids(text)
        assert "T1071" in result
        assert "T1059.001" in result

    def test_no_techniques(self) -> None:
        assert extract_technique_ids("No techniques mentioned here") == []

    def test_empty_string(self) -> None:
        assert extract_technique_ids("") == []

    def test_partial_id_not_matched(self) -> None:
        assert extract_technique_ids("T12 or T123 are not valid") == []

    def test_embedded_in_sentence(self) -> None:
        text = "The malware leverages T1547.001 (Registry Run Keys) for persistence."
        result = extract_technique_ids(text)
        assert result == ["T1547.001"]


# ---------------------------------------------------------------------------
# INDUSTRY_KEYWORDS structure
# ---------------------------------------------------------------------------


class TestIndustryKeywords:
    def test_has_expected_industries(self) -> None:
        expected = [
            "Banking",
            "Insurance",
            "Healthcare",
            "Energy",
            "Technology",
            "Manufacturing",
            "Retail",
            "Government",
            "Education",
            "Transportation",
        ]
        for industry in expected:
            assert industry in INDUSTRY_KEYWORDS, f"Missing: {industry}"

    def test_all_values_are_lists(self) -> None:
        for name, keywords in INDUSTRY_KEYWORDS.items():
            assert isinstance(keywords, list), f"{name} keywords not a list"
            assert len(keywords) > 0, f"{name} has no keywords"

    def test_keywords_are_lowercase(self) -> None:
        for name, keywords in INDUSTRY_KEYWORDS.items():
            for kw in keywords:
                assert kw == kw.lower(), f"{name}: keyword '{kw}' not lowercase"
