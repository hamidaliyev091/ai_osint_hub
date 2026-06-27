"""Tests for hub.cooking — deterministic data processing."""
import pytest
import sys
sys.path.insert(0, '/root/ai_osint_hub')

from hub.cooking import (
    parse_raw_input, generate_usernames, infer_emails,
    deduplicate, expand_hypotheses, can_expand,
    extract_emails, extract_domains, extract_urls,
    extract_usernames_from_urls, normalize_entity,
    score_confidence, CONFIDENCE,
)


class TestParseRawInput:
    def test_extracts_known_name(self):
        result = parse_raw_input("ali from baku")
        assert any(p["name"] == "Ali" for p in result["persons"])

    def test_extracts_email(self):
        result = parse_raw_input("contact me at test@example.com")
        assert "test@example.com" in result["emails"]

    def test_extracts_numeric_suffix(self):
        result = parse_raw_input("hamid 91 and aysan 007")
        assert "91" in result["numeric_suffixes"] or "007" in result["numeric_suffixes"]

    def test_empty_input(self):
        result = parse_raw_input("")
        assert result["persons"] == []
        assert result["emails"] == []

    def test_detects_username(self):
        result = parse_raw_input("github user hamid091")
        usernames = result.get("usernames", [])
        assert len(usernames) >= 1 or "hamid091" in str(result).lower()


class TestGenerateUsernames:
    def test_basic_username_gen(self):
        persons = [{"name": "Ali"}]
        usernames = generate_usernames(persons, [], [])
        assert "ali" in usernames

    def test_with_suffix(self):
        persons = [{"name": "Ali"}]
        usernames = generate_usernames(persons, ["91"], [])
        assert "ali91" in usernames

    def test_with_interest(self):
        persons = [{"name": "Ali"}]
        usernames = generate_usernames(persons, ["007"], ["chess"])
        assert any("chess" in u for u in usernames)


class TestInferEmails:
    def test_infers_gmail(self):
        emails = infer_emails(["testuser"], [])
        assert "testuser@gmail.com" in emails

    def test_custom_domain(self):
        emails = infer_emails(["admin"], ["example.com"])
        assert "admin@example.com" in emails

    def test_rejects_special_chars(self):
        emails = infer_emails(["bad user"], [])
        assert len(emails) == 0


class TestDeduplicate:
    def test_dedup_by_type_value(self):
        entities = [
            {"type": "email", "value": "test@test.com", "confidence": 0.8, "sources": ["a"]},
            {"type": "email", "value": "test@test.com", "confidence": 0.9, "sources": ["b"]},
        ]
        result = deduplicate(entities)
        assert len(result) == 1
        assert result[0]["confidence"] == 0.9

    def test_different_types_kept(self):
        entities = [
            {"type": "email", "value": "a@b.com", "sources": []},
            {"type": "username", "value": "a@b.com", "sources": []},
        ]
        result = deduplicate(entities)
        assert len(result) == 2


class TestCanExpand:
    def test_raw_input_can_expand(self):
        entity = {"type": "username", "value": "test", "metadata": {"origin": "raw_input"}}
        assert can_expand(entity) is True

    def test_tool_can_expand(self):
        entity = {"type": "email", "value": "x@y.com", "metadata": {"origin": "tool"}}
        assert can_expand(entity) is True

    def test_hypothesis_cannot_expand(self):
        entity = {"type": "username", "value": "test1", "metadata": {"origin": "hypothesis_expansion"}}
        assert can_expand(entity) is False

    def test_no_origin_cannot_expand(self):
        entity = {"type": "username", "value": "unknown", "metadata": {}}
        assert can_expand(entity) is False


class TestExpandHypotheses:
    def test_email_generates_username(self):
        entities = [{"type": "email", "value": "testuser@gmail.com", "metadata": {"origin": "raw_input"}}]
        result = expand_hypotheses(entities)
        assert any(h["type"] == "username" and h["value"] == "testuser" for h in result)

    def test_username_generates_variants(self):
        entities = [{"type": "username", "value": "alex", "metadata": {"origin": "raw_input"}}]
        result = expand_hypotheses(entities)
        assert any(h["value"] == "alex1" for h in result)

    def test_hypothesis_origin_blocked(self):
        entities = [{"type": "username", "value": "alex1", "metadata": {"origin": "hypothesis_expansion"}}]
        result = expand_hypotheses(entities)
        assert len(result) == 0


class TestExtractHelpers:
    def test_extract_emails(self):
        result = extract_emails("Contact a@b.com or c@d.org")
        assert len(result) == 2

    def test_extract_domains(self):
        result = extract_domains("Visit example.com or test.org")
        assert len(result) >= 1

    def test_extract_urls(self):
        result = extract_urls("See https://example.com/path for details")
        assert "https://example.com/path" in result

    def test_extract_usernames_from_urls(self):
        result = extract_usernames_from_urls(["https://github.com/hamid091"])
        assert any(r["username"] == "hamid091" for r in result)


class TestNormalizeEntity:
    def test_lowercases_email(self):
        result = normalize_entity({"type": "email", "value": "Test@Example.COM"})
        assert result["value"] == "test@example.com"

    def test_strips_at_from_username(self):
        result = normalize_entity({"type": "username", "value": "@testuser"})
        assert result["value"] == "testuser"


class TestScoreConfidence:
    def test_tool_output_base(self):
        result = score_confidence({"source": "tool_output"}, "holehe")
        assert 0.80 <= result <= 0.95

    def test_variant_low_confidence(self):
        result = score_confidence({"source": "variant_of_test"}, "")
        assert result <= 0.30

    def test_CONFIDENCE_constants(self):
        assert CONFIDENCE["parsed_email"] == 0.85
        assert CONFIDENCE["generated_username"] == 0.30
