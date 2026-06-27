"""Tests for hub.graph.memory — exposure graph operations."""
import pytest
import sys
sys.path.insert(0, '/root/ai_osint_hub')

from hub.graph.memory import (
    ExposureGraph, Node, Edge,
    ingest_entity, link_person_to_username,
    link_email_to_service, link_email_to_breach,
    link_username_to_email, _merge_metadata_preserve_origin,
)


class TestNode:
    def test_make_id(self):
        nid = Node.make_id("email", "Test@Example.COM")
        assert nid == "email:test@example.com"

    def test_node_creation(self):
        node = Node(node_id="test:1", type="test", value="val")
        assert node.confidence == 0.5
        assert node.sources == []


class TestExposureGraph:
    def test_add_node_returns_tuple(self):
        g = ExposureGraph()
        nid, is_new = g.add_node("email", "test@test.com")
        assert is_new is True
        assert "email:test@test.com" == nid

    def test_add_duplicate_returns_false(self):
        g = ExposureGraph()
        g.add_node("email", "test@test.com")
        _, is_new = g.add_node("email", "test@test.com")
        assert is_new is False

    def test_confidence_max_on_dup(self):
        g = ExposureGraph()
        g.add_node("email", "test@test.com", confidence=0.5)
        g.add_node("email", "test@test.com", confidence=0.9)
        node = g.get_node("email:test@test.com")
        assert node.confidence == 0.9

    def test_query(self):
        g = ExposureGraph()
        g.add_node("email", "test@test.com")
        nid = g.query("email", "test@test.com")
        assert nid == "email:test@test.com"

    def test_get_nodes_by_type(self):
        g = ExposureGraph()
        g.add_node("email", "a@b.com")
        g.add_node("email", "c@d.com")
        g.add_node("username", "test")
        emails = g.get_nodes_by_type("email")
        assert len(emails) == 2

    def test_add_edge(self):
        g = ExposureGraph()
        g.add_node("email", "a@b.com")
        g.add_node("service", "github")
        g.add_edge("email:a@b.com", "service:github", "REGISTERED_ON")
        assert len(g.edges) == 1

    def test_add_edge_missing_node_silent(self):
        g = ExposureGraph()
        g.add_node("email", "a@b.com")
        g.add_edge("email:a@b.com", "service:nonexistent", "REGISTERED_ON")
        assert len(g.edges) == 0

    def test_edge_dedup(self):
        g = ExposureGraph()
        g.add_node("email", "a@b.com")
        g.add_node("service", "github")
        g.add_edge("email:a@b.com", "service:github", "REGISTERED_ON", confidence=0.5)
        g.add_edge("email:a@b.com", "service:github", "REGISTERED_ON", confidence=0.9)
        assert len(g.edges) == 1
        assert g.edges[0].confidence == 0.9

    def test_summary(self):
        g = ExposureGraph()
        g.add_node("email", "a@b.com")
        summary = g.summary()
        assert summary["total_nodes"] == 1
        assert summary["total_edges"] == 0

    def test_serialization_roundtrip(self):
        g = ExposureGraph()
        g.add_node("email", "test@test.com", confidence=0.8, source="test",
                   metadata={"origin": "raw_input"})
        g.add_node("service", "github")
        g.add_edge("email:test@test.com", "service:github", "REGISTERED_ON")

        data = g.to_dict()
        g2 = ExposureGraph.from_dict(data)
        assert g2.summary() == g.summary()
        node = g2.get_node("email:test@test.com")
        assert node.metadata["origin"] == "raw_input"


class TestOriginPreservation:
    def test_raw_input_beats_tool(self):
        existing = {"origin": "raw_input", "other": "keep"}
        incoming = {"origin": "tool", "other": "new"}
        _merge_metadata_preserve_origin(existing, incoming)
        assert existing["origin"] == "raw_input"

    def test_tool_beats_hypothesis(self):
        existing = {"origin": "tool"}
        incoming = {"origin": "hypothesis_expansion", "data": "x"}
        _merge_metadata_preserve_origin(existing, incoming)
        assert existing["origin"] == "tool"
        assert existing["data"] == "x"  # non-origin fields merged


class TestIngestEntity:
    def test_ingest_returns_tuple(self):
        g = ExposureGraph()
        entity = {"type": "email", "value": "test@test.com", "confidence": 0.9,
                  "sources": ["tool:target"], "metadata": {}}
        nid, is_new = ingest_entity(g, entity, {"email": "test@test.com"}, "holehe", "2024-01-01T00:00:00")
        assert is_new is True

    def test_ingest_sets_tool_origin(self):
        g = ExposureGraph()
        entity = {"type": "email", "value": "x@y.com", "metadata": {}}
        ingest_entity(g, entity, {"email": "x@y.com"}, "holehe", "now")
        node = g.get_node("email:x@y.com")
        assert node.metadata.get("origin") == "tool"


class TestLinkHelpers:
    def test_link_person_to_username(self):
        g = ExposureGraph()
        g.add_node("person", "hamid")
        g.add_node("username", "hamid091")
        link_person_to_username(g, "person:hamid", "username:hamid091")
        assert len(g.edges) == 1
        assert g.edges[0].type == "HAS_USERNAME"
