"""Phase 15 precision tests — strict handles, maigret target filter, graph layout, role semantics."""

from __future__ import annotations

import json
import re
import shutil
import subprocess

import pytest

from hub.erkg.store import ERKGStore
from hub.intake import MultiClueIntake, StructuredSeeds
from hub.models import EntityType, is_functional_predicate
from hub.tools.parsers.maigret import parse as parse_maigret
from hub.web import WORKBENCH_HTML
from tests import support


# ════════════════════════════════════════════════════════════════════════
# 1. Strict free-text handle extraction (no prose/ordinal seeds)
# ════════════════════════════════════════════════════════════════════════

PROSE = (
    "elvin taskin\n"
    "studies in baku technical institute\n"
    "2nd course information security student\n"
    "will be 18 in a few days"
)


def _usernames(raw: str, structured=None):
    return [clue.value for clue in MultiClueIntake().extract(
        raw, StructuredSeeds.from_mapping(structured or {}))
        if clue.entity_type == EntityType.USERNAME]


class TestStrictFreeTextHandles:
    def test_prose_ordinals_are_never_usernames(self):
        assert _usernames(PROSE) == []
        assert all(value not in {"2nd", "18", "2026", "c2", "v2", "3rd", "1st"}
                   for value in _usernames(PROSE))

    def test_prose_with_structured_usernames_adds_no_false_usernames(self):
        out = _usernames(PROSE, {"usernames": ["explicit_user"]})
        assert "explicit_user" in out
        for wrong in ("2nd", "18", "student", "course", "baku"):
            assert wrong not in out

    def test_explicit_cues_are_extracted(self):
        cases = {
            "username: foo_bar": "foo_bar",
            "user: foo": "foo",
            "handle: foo-bar": "foo-bar",
            "nick: username_42": "username_42",
            "nickname: foobar": "foobar",
            "aka foobar": "foobar",
            "u/alice": "alice",
            "@alice": "alice",
            "https://github.com/alice": "alice",
        }
        for raw, expected in cases.items():
            assert expected in _usernames(raw), raw
        assert "foo_bar" in _usernames("username: foo_bar")

    def test_explicit_cue_can_list_two_handles(self):
        out = _usernames("goes by elv1ntsk and 108.elv1n")
        assert "elv1ntsk" in out
        assert "108.elv1n" in out

    def test_prose_digit_tokens_are_not_handles(self):
        raw = ("user studies 2nd course, 18 years old, c2 server, v2 api, "
               "sha256 hash, ipv4 address, http2 traffic, web3 wallet")
        assert _usernames(raw) == []

    def test_single_bare_target_still_usable(self):
        assert _usernames("hamid091") == ["hamid091"]
        assert _usernames("2nd") == []
        assert _usernames("18") == []


# ════════════════════════════════════════════════════════════════════════
# 2. Maigret parser target/collateral filtering
# ════════════════════════════════════════════════════════════════════════

class TestMaigretTargetFiltering:
    def test_text_rejects_generic_and_collateral_profiles(self):
        raw = (
            "[+] YouTube: https://www.youtube.com/about\n"
            "[+] Shame: https://www.youtube.com/shame\n"
            "[+] Humidify: https://github.com/humidify\n"
            "[+] GitHub: https://github.com/elv1n\n"
        )
        out = parse_maigret(raw, target="elv1n")
        profiles = {entity.value for entity in out.entities
                    if entity.type is EntityType.SOCIAL_PROFILE}
        assert profiles == {"https://github.com/elv1n"}
        assert all(relation.subject_value == "elv1n"
                   for relation in out.relations)

    def test_json_rejects_generic_and_collateral_profiles(self):
        payload = {
            "sites": {
                "YouTube": {
                    "status": {"is_claimed": True},
                    "url_user": "https://www.youtube.com/about",
                    "username": "shame",
                },
                "Humidify": {
                    "status": {"is_claimed": True},
                    "url_user": "https://example.com/humidify",
                    "username": "humidify",
                },
                "GitHub": {
                    "status": {"is_claimed": True},
                    "url_user": "https://github.com/elv1n",
                },
            }
        }
        out = parse_maigret(json.dumps(payload), target="elv1n")
        profiles = {entity.value for entity in out.entities
                    if entity.type is EntityType.SOCIAL_PROFILE}
        assert profiles == {"https://github.com/elv1n"}
        assert [relation.subject_value for relation in out.relations] == ["elv1n"]

    def test_target_handle_with_dot_is_kept(self):
        payload = {"sites": {"GitHub": {
            "status": {"is_claimed": True},
            "url_user": "https://github.com/108.elv1n",
        }}}
        out = parse_maigret(json.dumps(payload), target="108.elv1n")
        profiles = {entity.value for entity in out.entities
                    if entity.type is EntityType.SOCIAL_PROFILE}
        assert profiles == {"https://github.com/108.elv1n"}

    def test_existing_fixture_target_kept(self):
        fixture = (__import__("pathlib").Path(__file__).resolve().parent
                   / "fixtures" / "parsers" / "maigret_sample.txt").read_text(
                       encoding="utf-8")
        out = parse_maigret(fixture, target="alice")
        profiles = {entity.value for entity in out.entities
                    if entity.type is EntityType.SOCIAL_PROFILE}
        assert {"https://github.com/alice", "https://twitter.com/alice"} <= profiles
        assert all(relation.subject_value == "alice"
                   for relation in out.relations)


# ════════════════════════════════════════════════════════════════════════
# 3. Multi-valued role attributes never contradict
# ════════════════════════════════════════════════════════════════════════

class TestRoleSemantics:
    def test_role_attribute_is_non_functional(self):
        assert is_functional_predicate("HAS_ATTRIBUTE:role") is False
        assert is_functional_predicate("HAS_ATTRIBUTE:clue_field") is False
        assert is_functional_predicate("HAS_ATTRIBUTE:provenance") is False
        assert is_functional_predicate("HAS_ATTRIBUTE:registered") is True
        assert is_functional_predicate("HAS_EMAIL") is True

    def test_mail_domain_and_registrable_parent_do_not_contradict(
            self, store_factory):
        store = store_factory()
        support.bootstrap(store)
        domain = support.entity(store, EntityType.DOMAIN, "example.edu.az")
        first = support.claim(
            store, domain.entity_id, "HAS_ATTRIBUTE:role",
            object_literal="mail_domain", tools=("seed",))
        second = support.claim(
            store, domain.entity_id, "HAS_ATTRIBUTE:role",
            object_literal="registrable_parent", tools=("virustotal_lookup",))
        assert first.status.value == "SINGLE_SOURCE_LEAD"
        assert second.status.value == "SINGLE_SOURCE_LEAD"
        assert store.list_contradictions(support.DEFAULT_INV) == []

    def test_registered_attribute_remains_functional(self, store_factory):
        store = store_factory()
        support.bootstrap(store)
        domain = support.entity(store, EntityType.DOMAIN, "example.com")
        support.claim(store, domain.entity_id, "HAS_ATTRIBUTE:registered",
                      object_literal=True, tools=("seed",))
        support.claim(store, domain.entity_id, "HAS_ATTRIBUTE:registered",
                      object_literal=False, tools=("virustotal_lookup",))
        assert store.list_contradictions(support.DEFAULT_INV)


# ════════════════════════════════════════════════════════════════════════
# 4. Graph layout: radial, no rectangle wall-clamping
# ════════════════════════════════════════════════════════════════════════

class TestGraphLayoutPrecision:
    def test_no_rectangular_coordinate_clamp(self):
        assert "Math.max(24, Math.min(width - 24" not in WORKBENCH_HTML
        assert "positions[id].x = Math.max(24" not in WORKBENCH_HTML
        for marker in ("k_radial", "maxRadius", "fitRadius",
                       "aspect-preserving fit"):
            assert marker in WORKBENCH_HTML, marker

    @pytest.mark.skipif(shutil.which("node") is None,
                        reason="node.js unavailable for layout simulation")
    def test_150_node_layout_stays_off_the_rectangular_wall(self, tmp_path):
        match = re.search(r"<script>(.*?)</script>", WORKBENCH_HTML, re.S)
        assert match is not None
        script = match.group(1)
        start = script.index("function layoutGraph(nodes, edges) {")
        end = script.index("function renderGraph(payload) {", start)
        layout_js = script[start:end]
        harness = """
const fs = require('fs');
const INNER_RING_TYPES = {username:true, email:true, phone:true,
                          organization:true, location:true};
eval('(' + fs.readFileSync(process.argv[1], 'utf8') + ')');
const nodes = [{id:'person', type:'person'}];
for (let i = 0; i < 149; i += 1) {
  nodes.push({id:'n' + i, type: i % 2 ? 'domain' : 'username'});
}
const positions = layout_global(nodes, []);
console.log(JSON.stringify(positions));
"""
        harness = harness.replace("eval('(' + fs.readFileSync(process.argv[1], 'utf8') + ')');",
                                  "globalThis.layout_global = eval('(' + "
                                  "fs.readFileSync(process.argv[2], 'utf8') + ')');")
        js_path = tmp_path / "layout.js"
        js_path.write_text(layout_js, encoding="utf-8")
        harness_path = tmp_path / "harness.js"
        harness_path.write_text(harness, encoding="utf-8")
        completed = subprocess.run(
            [shutil.which("node"), str(harness_path), str(js_path)],
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=30, check=False,
        )
        assert completed.returncode == 0, completed.stderr
        positions = json.loads(completed.stdout)
        assert len(positions) == 150
        width, height = 960, 620
        cx, cy = width / 2, height / 2
        fit_radius = min(width, height) / 2 - 42
        for node_id, position in positions.items():
            x, y = float(position["x"]), float(position["y"])
            assert x == x and y == y  # finite
            # No node may sit on the old hard rectangular walls.
            assert x not in (24, width - 24)
            assert y not in (24, height - 24)
            assert (x - cx) ** 2 + (y - cy) ** 2 <= (fit_radius + 0.5) ** 2
        # The fit must remain a circle, not a square frame: corners stay empty.
        corner_nodes = [
            node_id for node_id, position in positions.items()
            if abs(float(position["x"]) - cx) > fit_radius * 0.85
            and abs(float(position["y"]) - cy) > fit_radius * 0.85
        ]
        assert len(corner_nodes) < 20


# ════════════════════════════════════════════════════════════════════════
# 5. Transient fetch UX
# ════════════════════════════════════════════════════════════════════════

class TestTransientFetchUX:
    def test_transient_fetch_errors_are_silent_and_retried(self):
        assert "isTransientNetworkError" in WORKBENCH_HTML
        assert "failed to fetch" in WORKBENCH_HTML.lower()
        assert "transientError" in WORKBENCH_HTML
        refresh = WORKBENCH_HTML[WORKBENCH_HTML.index("function refreshState()"):]
        refresh = refresh[:refresh.index("var INNER_RING_TYPES")]
        assert "isTransientNetworkError" in refresh
        assert "setTimeout" in refresh
        assert "clearError()" in refresh

    def test_ui_message_cleared_on_status_and_data_updates(self):
        assert "clearError();" in WORKBENCH_HTML
        render = WORKBENCH_HTML[WORKBENCH_HTML.index("function renderGraph(payload)"):]
        render = render[:render.index("function inspectEntity")]
        assert "clearError()" in render
        status = WORKBENCH_HTML[WORKBENCH_HTML.index("function setStatus(text, completed)"):]
        status = status[:status.index("function showError")]
        assert "clearError()" in status
