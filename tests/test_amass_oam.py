"""amass v4 OAM graph-format parser tests."""

from hub.models import EdgeType, EntityType
from hub.tools.parsers.amass import parse

OAM_SAMPLE = """
example.com (FQDN) --> ns_record --> hera.ns.cloudflare.com (FQDN)
example.com (FQDN) --> ns_record --> elliott.ns.cloudflare.com (FQDN)
hera.ns.cloudflare.com (FQDN) --> a_record --> 173.245.58.162 (IPAddress)
hera.ns.cloudflare.com (FQDN) --> aaaa_record --> 2606:4700:50::adf5:3aa2 (IPAddress)
13335 (ASN) --> managed_by --> CLOUDFLARENET - Cloudflare, Inc. (RIROrganization)
13335 (ASN) --> announces --> 172.64.0.0/18 (Netblock)
172.64.0.0/18 (Netblock) --> contains --> 172.64.32.162 (IPAddress)
"""


class TestAmassOamFormat:
    def test_entities_extracted(self):
        output = parse(OAM_SAMPLE, "example.com")
        types = {entity.type for entity in output.entities}
        assert EntityType.SUBDOMAIN in types
        assert EntityType.IP in types
        assert EntityType.ASN in types
        assert EntityType.ORGANIZATION in types
        values = {entity.value for entity in output.entities}
        assert "AS13335" in values
        assert "173.245.58.162" in values
        assert any("cloudflare" in value.lower() for value in values)

    def test_resolves_to_relation(self):
        output = parse(OAM_SAMPLE, "example.com")
        relations = [relation for relation in output.relations
                     if relation.predicate == EdgeType.RESOLVES_TO]
        assert relations
        assert relations[0].object_value in {"173.245.58.162", "2606:4700:50::adf5:3aa2"}
        assert relations[0].evidence and "-->" in relations[0].evidence

    def test_evidence_snippets_are_lines(self):
        output = parse(OAM_SAMPLE, "example.com")
        for entity in output.entities:
            assert entity.evidence
            assert "-->" in entity.evidence or entity.evidence in OAM_SAMPLE

    def test_garbage_and_empty_do_not_raise(self):
        assert parse("", "example.com").is_empty
        assert parse("The enumeration has finished\n[INF] starting", "example.com").is_empty
        assert parse("--> broken (FQDN)", "example.com").is_empty

    def test_mixed_oam_and_jsonl(self):
        mixed = OAM_SAMPLE + '\n{"name":"api.example.com","domain":"example.com",' \
                             '"addresses":[{"ip":"8.8.8.8"}]}\n'
        output = parse(mixed, "example.com")
        values = {entity.value for entity in output.entities}
        assert "api.example.com" in values
        assert "8.8.8.8" in values
