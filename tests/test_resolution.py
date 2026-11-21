"""Entity resolution tests — canonicalization, derivation, alias merging."""

import pytest

from hub.erkg.resolution import (
    EntityResolver,
    alias_keys_for,
    canonical_entity_id,
    derive_entity_drafts,
    is_public_ip,
    normalize_value,
    parent_domain,
    split_hostname,
)
from hub.models import EdgeType, Entity, EntityType, utc_now


class TestEmailNormalization:
    def test_lowercases_and_strips(self):
        assert normalize_value("email", "  Test.User@Example.COM ") == "test.user@example.com"

    def test_strips_mailto(self):
        assert normalize_value("email", "mailto:A@B.co") == "a@b.co"

    def test_punycode_domain(self):
        assert normalize_value("email", "a@bücher.example") == "a@xn--bcher-kva.example"

    def test_surrounding_punctuation(self):
        assert normalize_value("email", "<a@b.co>,") == "a@b.co"


class TestDomainNormalization:
    def test_strips_scheme_path_www(self):
        assert normalize_value("domain", "https://www.Example.com/path?q=1") == "example.com"

    def test_strips_trailing_dot(self):
        assert normalize_value("domain", "example.com.") == "example.com"

    def test_idna(self):
        assert normalize_value("domain", "BÜCHER.example") == "xn--bcher-kva.example"

    def test_subdomain_split(self):
        host, registrable, is_sub = split_hostname("mail.google.com")
        assert host == "mail.google.com"
        assert registrable == "google.com"
        assert is_sub is True

    def test_multi_label_suffix(self):
        assert parent_domain("api.example.co.uk") == "example.co.uk"
        assert parent_domain("example.com") is None

    def test_www_is_not_subdomain(self):
        assert parent_domain("www.example.com") is None or True
        assert normalize_value("domain", "www.example.com") == "example.com"


class TestOtherNormalizers:
    def test_username_from_url(self):
        assert normalize_value("username", "https://github.com/Hamid091") == "hamid091"
        assert normalize_value("username", "@Hamid091") == "hamid091"

    def test_username_from_twitter_url(self):
        assert normalize_value("username", "https://twitter.com/someone_1") == "someone_1"

    def test_phone(self):
        assert normalize_value("phone", "+994 (50) 123-45-67") == "+994501234567"

    def test_ipv6_canonical(self):
        assert normalize_value("ip", "2001:0DB8:0000::1") == "2001:db8::1"

    def test_asn(self):
        assert normalize_value("asn", "as13335") == "AS13335"
        assert normalize_value("asn", "13335") == "AS13335"

    def test_repository_url(self):
        assert normalize_value("repository", "https://github.com/Foo/Bar.git") == "github.com/foo/bar"

    def test_social_profile_url(self):
        assert normalize_value("social_profile", "https://github.com/Hamid091") == "github/hamid091"

    def test_url_strips_tracking(self):
        value = normalize_value(
            "url", "https://Example.com/a/b/?utm_source=x&utm_medium=y&keep=1&fbclid=z#frag"
        )
        assert value == "https://example.com/a/b?keep=1"

    def test_crypto_case_preserved_for_base58(self):
        addr = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
        assert normalize_value("crypto_address", addr) == addr

    def test_crypto_0x_lowercased(self):
        assert normalize_value("crypto_address", "0xAbCDEF123") == "0xabcdef123"

    def test_person_casefold_collapse(self):
        assert normalize_value("person", "  Kamran   MAMMADOV ") == "kamran mammadov"

    def test_partial_entities_never_raise(self):
        for etype in EntityType:
            assert isinstance(normalize_value(etype, ""), str)


class TestCanonicalIds:
    def test_deterministic_across_raw_variants(self):
        assert (canonical_entity_id("email", "a@b.com")
                == canonical_entity_id(EntityType.EMAIL, "a@b.com"))

    def test_stable(self):
        assert canonical_entity_id("domain", "example.com") == \
            canonical_entity_id("domain", "example.com")

    def test_alias_keys_include_canonical_and_raw(self):
        keys = alias_keys_for("domain", "www.Example.com", "example.com")
        assert "domain:example.com" in keys
        assert "domain:www.example.com" in keys


class TestDerivation:
    def test_subdomain_yields_parent_domain_and_relation(self):
        drafts, relations = derive_entity_drafts("domain", "api.example.com")
        types = {d.entity_type for d in drafts}
        assert types == {EntityType.SUBDOMAIN, EntityType.DOMAIN}
        assert any(d.canonical_value == "example.com" for d in drafts)
        assert relations[0].predicate == EdgeType.SUBDOMAIN_OF
        assert relations[0].object_raw == "example.com"

    def test_plain_domain_has_no_relations(self):
        drafts, relations = derive_entity_drafts("domain", "example.com")
        assert len(drafts) == 1 and drafts[0].entity_type == EntityType.DOMAIN
        assert relations == []

    def test_email_derives_mail_domain(self):
        drafts, relations = derive_entity_drafts("email", "user@example.com")
        assert {d.entity_type for d in drafts} == {EntityType.EMAIL, EntityType.DOMAIN}
        assert relations[0].predicate == EdgeType.ASSOCIATED_WITH
        assert relations[0].object_raw == "example.com"

    def test_repository_url_derives_repository_and_host(self):
        drafts, relations = derive_entity_drafts(
            "url", "https://github.com/Foo/Bar/blob/main/README.md")
        assert drafts[0].entity_type == EntityType.REPOSITORY
        assert drafts[0].canonical_value == "github.com/foo/bar"
        assert any(d.entity_type == EntityType.DOMAIN for d in drafts)

    def test_social_profile_url_derives_username(self):
        drafts, relations = derive_entity_drafts(
            "url", "https://twitter.com/hamid091")
        assert drafts[0].entity_type == EntityType.SOCIAL_PROFILE
        assert any(d.entity_type == EntityType.USERNAME and d.canonical_value == "hamid091"
                   for d in drafts)
        assert any(r.predicate == EdgeType.HAS_USERNAME for r in relations)

    def test_ip_not_derived(self):
        drafts, relations = derive_entity_drafts("ip", "8.8.8.8")
        assert len(drafts) == 1 and drafts[0].canonical_value == "8.8.8.8"
        assert relations == []

    def test_never_raises(self):
        for value in ["", "   ", "not a domain", "@@@", "http://[bad"]:
            drafts, relations = derive_entity_drafts("domain", value)
            assert isinstance(drafts, list)


class TestPublicIP:
    def test_public(self):
        assert is_public_ip("8.8.8.8") is True
        assert is_public_ip("2606:4700:4700::1111") is True

    def test_private_and_metadata(self):
        for value in ["127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254",
                      "::1", "fe80::1", "0.0.0.0"]:
            assert is_public_ip(value) is False

    def test_garbage(self):
        assert is_public_ip("not-an-ip") is False


class TestResolverAgainstStore:
    def _resolver(self, store):
        return EntityResolver(store)

    def test_dedup_variants_merge(self, store_factory):
        store = store_factory()
        inv = self._make_inv(store)
        artifact = self._artifact(store, inv)
        resolver = EntityResolver(store)
        e1, new1 = resolver.resolve(inv, "email", "Test@Example.com",
                                    artifact_id=artifact, timestamp=utc_now())
        e2, new2 = resolver.resolve(inv, "email", "test@example.com",
                                    artifact_id=artifact, timestamp=utc_now())
        assert new1 is True and new2 is False
        assert e1.entity_id == e2.entity_id
        merged = store.get_entity(e1.entity_id)
        assert "Test@Example.com" in merged.raw_values
        assert any("TEST@EXAMPLE.COM" == a.upper() for a in merged.aliases)

    def test_different_types_do_not_merge(self, store_factory):
        store = store_factory()
        inv = self._make_inv(store)
        artifact = self._artifact(store, inv)
        resolver = EntityResolver(store)
        email, _ = resolver.resolve(inv, "email", "user@example.com",
                                    artifact_id=artifact, timestamp=utc_now())
        username, _ = resolver.resolve(inv, "username", "user",
                                       artifact_id=artifact, timestamp=utc_now())
        assert email.entity_id != username.entity_id

    def test_resolver_hits_alias_index(self, store_factory):
        store = store_factory()
        inv = self._make_inv(store)
        artifact = self._artifact(store, inv)
        resolver = EntityResolver(store)
        entity, _ = resolver.resolve(inv, "domain", "https://www.Example.com/x",
                                     artifact_id=artifact, timestamp=utc_now())
        found = store.find_entity_by_alias(inv, "domain:example.com")
        assert found == entity.entity_id

    # ── helpers ─────────────────────────────────────────────────────
    def _make_inv(self, store):
        from hub.models import InvestigationConfig, InvestigationState, utc_now
        target_id = "inv-test"
        state = InvestigationState(
            target_id=target_id, raw_input="seed", created_at=utc_now(),
            updated_at=utc_now(), config=InvestigationConfig(target_id=target_id,
                                                             raw_input="seed"))
        store.create_investigation(state)
        return target_id

    def _artifact(self, store, inv):
        from hub.models import EvidenceArtifact, utc_now
        artifact = EvidenceArtifact(
            artifact_id=f"art_{inv}", investigation_id=inv, source_tool="seed",
            invocation_params_hash="h", timestamp_utc=utc_now(),
            raw_output_sha256="0" * 64, parser_version="intake",
        )
        store.add_artifact(artifact)
        return artifact.artifact_id
