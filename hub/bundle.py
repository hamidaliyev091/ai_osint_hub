"""Portable OSINT case bundles (``.osintcase.zip``) with strict security validation.

Provides WAL-safe SQLite snapshot export (with optional PII/secret redaction)
and hardened ZIP import defending against Zip-Slip, symlinks, decompression
bombs, spoofed ZIP headers, and corrupted/tampered databases.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from hub.erkg.store import default_home
from hub.models import sha256_text, utc_now
from hub.security.redaction import redact

BUNDLE_FORMAT = "ai-osint-hub-case-bundle"
BUNDLE_FORMAT_VERSION = "2.0.0"
BUNDLE_EXTENSION = ".osintcase.zip"

MAX_BUNDLE_BYTES = 50 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 150 * 1024 * 1024
MAX_COMPRESSION_RATIO = 50.0
MAX_BUNDLE_MEMBERS = 500

_CHUNK_BYTES = 64 * 1024
_TARGET_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SAFE_RAW_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,200}$")

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE_RE = re.compile(
    r"(?<!\w)(?:"
    r"\+\d{1,3}(?:[-.\s()]*\d{2,4}){2,4}"
    r"|(?:\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}"
    r"|\+\d{7,15}"
    r")(?!\w)"
)
_TOKEN_RE = re.compile(
    r"\b(?:"
    r"sk-[A-Za-z0-9_-]{12,}"
    r"|ghp_[A-Za-z0-9]{16,}"
    r"|github_pat_[A-Za-z0-9_]{16,}"
    r"|AIza[A-Za-z0-9_-]{16,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"
    r"|AKIA[0-9A-Z]{16}"
    r")\b"
)

_TEXT_RAW_EXTENSIONS = frozenset({
    ".txt", ".json", ".log", ".md", ".csv", ".tsv", ".xml", ".html", ".yaml", ".yml",
})


def _validate_target_id(target_id: Any) -> str:
    text = str(target_id or "").strip()
    if (
        not text
        or text in {".", ".."}
        or ".." in text
        or "/" in text
        or "\\" in text
        or ":" in text
        or "\x00" in text
        or not _TARGET_ID_RE.match(text)
    ):
        raise ValueError(f"Invalid target_id: {target_id!r}")
    return text


def redact_pii_text(text: Any) -> str:
    """Scrub registered secrets, API token patterns, emails, and phone numbers."""
    if text is None:
        return ""
    value = redact(str(text))
    if not value:
        return value
    value = _TOKEN_RE.sub("[REDACTED:TOKEN]", value)
    value = _EMAIL_RE.sub("[REDACTED:EMAIL]", value)

    def _phone_sub(match: re.Match[str]) -> str:
        digits = sum(1 for ch in match.group(0) if ch.isdigit())
        if 7 <= digits <= 15:
            return "[REDACTED:PHONE]"
        return match.group(0)

    return _PHONE_RE.sub(_phone_sub, value)


def _redact_json_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_pii_text(value)
    if isinstance(value, list):
        return [_redact_json_value(item) for item in value]
    if isinstance(value, dict):
        return {redact_pii_text(k) if isinstance(k, str) else k: _redact_json_value(v) for k, v in value.items()}
    return value


def redact_pii_json(raw_json: str) -> str:
    """Redact PII/secrets inside a JSON-serialized column while preserving valid JSON."""
    if not raw_json:
        return raw_json
    try:
        parsed = json.loads(raw_json)
    except ValueError:
        return redact_pii_text(raw_json)
    return json.dumps(_redact_json_value(parsed), ensure_ascii=False)


def _resolve_export_case_dir(
    state_root: Path | str | None,
    target_id: str,
    investigations_dir: Path | str | None = None,
) -> Path:
    if investigations_dir is not None:
        inv_root = Path(investigations_dir).expanduser().resolve()
        candidate = inv_root / target_id
        if (candidate / "erkg.sqlite3").is_file():
            return candidate
        raise FileNotFoundError(f"Investigation {target_id!r} not found under {inv_root}")

    if state_root is None:
        inv_root = (default_home() / "investigations").resolve()
        candidate = inv_root / target_id
        if (candidate / "erkg.sqlite3").is_file():
            return candidate
        raise FileNotFoundError(f"Investigation {target_id!r} not found under {inv_root}")

    root = Path(state_root).expanduser().resolve()
    candidates = [
        root / "investigations" / target_id,
        root / target_id,
    ]
    for cand in candidates:
        if (cand / "erkg.sqlite3").is_file():
            return cand
    raise FileNotFoundError(f"Investigation {target_id!r} not found under {root}")


def _resolve_import_inv_dir(
    state_root: Path | str | None,
    investigations_dir: Path | str | None = None,
) -> Path:
    if investigations_dir is not None:
        return Path(investigations_dir).expanduser().resolve()
    if state_root is None:
        return (default_home() / "investigations").resolve()
    root = Path(state_root).expanduser().resolve()
    if root.name == "investigations":
        return root
    return (root / "investigations").resolve()


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def _scrub_sqlite_copy(db_path: Path) -> None:
    """Scrub PII and secrets across all ERKG tables inside a temporary DB copy."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA trusted_schema = OFF;")
        conn.execute("PRAGMA foreign_keys = OFF;")
        conn.execute("BEGIN IMMEDIATE")

        for row in conn.execute(
            "SELECT target_id, raw_input, config_json, stop_reason, objectives_json FROM investigations"
        ).fetchall():
            conn.execute(
                """UPDATE investigations
                   SET raw_input=?, config_json=?, stop_reason=?, objectives_json=?
                   WHERE target_id=?""",
                (
                    redact_pii_text(row["raw_input"]),
                    redact_pii_json(row["config_json"]),
                    redact_pii_text(row["stop_reason"]) if row["stop_reason"] is not None else None,
                    redact_pii_json(row["objectives_json"]),
                    row["target_id"],
                ),
            )

        for row in conn.execute("SELECT artifact_id, raw_evidence_snippet FROM artifacts").fetchall():
            conn.execute(
                "UPDATE artifacts SET raw_evidence_snippet=? WHERE artifact_id=?",
                (redact_pii_text(row["raw_evidence_snippet"]), row["artifact_id"]),
            )

        # Preserve UNIQUE (investigation_id, type, canonical_value) if multiple emails/phones redact.
        seen_canonical: set[tuple[str, str, str]] = set()
        for row in conn.execute(
            "SELECT entity_id, investigation_id, type, canonical_value, display_value, "
            "aliases_json, raw_values_json, metadata_json FROM entities ORDER BY entity_id"
        ).fetchall():
            orig_canon = row["canonical_value"]
            new_canon = redact_pii_text(orig_canon)
            key = (row["investigation_id"], row["type"], new_canon)
            if key in seen_canonical:
                new_canon = f"{new_canon}#{sha256_text(orig_canon)[:8]}"
                key = (row["investigation_id"], row["type"], new_canon)
            seen_canonical.add(key)
            conn.execute(
                """UPDATE entities
                   SET canonical_value=?, display_value=?, aliases_json=?,
                       raw_values_json=?, metadata_json=?
                   WHERE entity_id=?""",
                (
                    new_canon,
                    redact_pii_text(row["display_value"]),
                    redact_pii_json(row["aliases_json"]),
                    redact_pii_json(row["raw_values_json"]),
                    redact_pii_json(row["metadata_json"]),
                    row["entity_id"],
                ),
            )

        seen_aliases: set[tuple[str, str]] = set()
        for row in conn.execute(
            "SELECT rowid, investigation_id, alias_key FROM entity_aliases ORDER BY rowid"
        ).fetchall():
            orig_alias = row["alias_key"]
            new_alias = redact_pii_text(orig_alias)
            akey = (row["investigation_id"], new_alias)
            if akey in seen_aliases:
                new_alias = f"{new_alias}#{sha256_text(orig_alias)[:8]}"
                akey = (row["investigation_id"], new_alias)
            seen_aliases.add(akey)
            if new_alias != orig_alias:
                conn.execute(
                    "UPDATE entity_aliases SET alias_key=? WHERE rowid=?",
                    (new_alias, row["rowid"]),
                )

        for row in conn.execute("SELECT claim_id, object_literal FROM claims WHERE object_literal IS NOT NULL").fetchall():
            conn.execute(
                "UPDATE claims SET object_literal=? WHERE claim_id=?",
                (redact_pii_json(row["object_literal"]), row["claim_id"]),
            )

        for row in conn.execute("SELECT rowid, snippet FROM claim_artifacts").fetchall():
            conn.execute(
                "UPDATE claim_artifacts SET snippet=? WHERE rowid=?",
                (redact_pii_text(row["snippet"]), row["rowid"]),
            )

        for row in conn.execute("SELECT rowid, error_message FROM execution_ledger").fetchall():
            if row["error_message"]:
                conn.execute(
                    "UPDATE execution_ledger SET error_message=? WHERE rowid=?",
                    (redact_pii_text(row["error_message"]), row["rowid"]),
                )

        for row in conn.execute(
            "SELECT hypothesis_id, question, rationale, closing_note FROM hypotheses"
        ).fetchall():
            conn.execute(
                "UPDATE hypotheses SET question=?, rationale=?, closing_note=? WHERE hypothesis_id=?",
                (
                    redact_pii_text(row["question"]),
                    redact_pii_text(row["rationale"]),
                    redact_pii_text(row["closing_note"]),
                    row["hypothesis_id"],
                ),
            )

        for row in conn.execute("SELECT rowid, record_json FROM iterations").fetchall():
            conn.execute(
                "UPDATE iterations SET record_json=? WHERE rowid=?",
                (redact_pii_json(row["record_json"]), row["rowid"]),
            )

        if _table_exists(conn, "ai_insights"):
            for row in conn.execute("SELECT insight_id, summary, payload_json FROM ai_insights").fetchall():
                conn.execute(
                    "UPDATE ai_insights SET summary=?, payload_json=? WHERE insight_id=?",
                    (
                        redact_pii_text(row["summary"]),
                        redact_pii_json(row["payload_json"]),
                        row["insight_id"],
                    ),
                )

        conn.execute("COMMIT")
        # Rebuild database pages so scrubbed PII cannot linger in SQLite freelist pages.
        conn.execute("VACUUM")
    finally:
        conn.close()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def export_case_bundle(
    state_root: Path | str | None,
    target_id: str,
    out_path: Path | str | None = None,
    *,
    redact_pii: bool = False,
    investigations_dir: Path | str | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Export an investigation into a self-contained, SHA-256-verified ``.osintcase.zip``."""
    tid = _validate_target_id(target_id)
    case_dir = _resolve_export_case_dir(state_root, tid, investigations_dir=investigations_dir)
    src_db = case_dir / "erkg.sqlite3"
    if not src_db.is_file():
        raise FileNotFoundError(f"Missing erkg.sqlite3 for {tid!r}")

    with tempfile.TemporaryDirectory(prefix="osint_bundle_export_") as tmp_dir:
        tmp_path = Path(tmp_dir)
        staged_db = tmp_path / "erkg.sqlite3"

        src_conn = sqlite3.connect(str(src_db), timeout=5.0)
        dst_conn = sqlite3.connect(str(staged_db))
        try:
            src_conn.backup(dst_conn)
            dst_conn.execute("PRAGMA journal_mode=DELETE;")
            dst_conn.commit()
        finally:
            dst_conn.close()
            src_conn.close()

        if redact_pii:
            _scrub_sqlite_copy(staged_db)

        db_bytes = staged_db.read_bytes()
        files_manifest: dict[str, dict[str, Any]] = {
            "erkg.sqlite3": {
                "sha256": _sha256_bytes(db_bytes),
                "size": len(db_bytes),
            }
        }
        archive_entries: list[tuple[str, bytes]] = [("erkg.sqlite3", db_bytes)]

        raw_dir = case_dir / "raw"
        if raw_dir.is_dir():
            for child in sorted(raw_dir.iterdir(), key=lambda p: p.name):
                if child.is_symlink() or not child.is_file():
                    continue
                if not _SAFE_RAW_NAME_RE.match(child.name) or child.name in {".", ".."}:
                    continue
                raw_bytes = child.read_bytes()
                if redact_pii and child.suffix.lower() in _TEXT_RAW_EXTENSIONS:
                    text = raw_bytes.decode("utf-8", errors="replace")
                    raw_bytes = redact_pii_text(text).encode("utf-8")
                arc_name = f"raw/{child.name}"
                files_manifest[arc_name] = {
                    "sha256": _sha256_bytes(raw_bytes),
                    "size": len(raw_bytes),
                }
                archive_entries.append((arc_name, raw_bytes))

        if len(archive_entries) + 1 > MAX_BUNDLE_MEMBERS:
            raise ValueError(
                f"Bundle member count ({len(archive_entries) + 1}) exceeds MAX_BUNDLE_MEMBERS ({MAX_BUNDLE_MEMBERS})"
            )

        total_uncompressed = sum(len(data) for _, data in archive_entries)
        if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
            raise ValueError(
                f"Uncompressed case size ({total_uncompressed} bytes) exceeds MAX_UNCOMPRESSED_BYTES"
            )

        manifest: dict[str, Any] = {
            "format": BUNDLE_FORMAT,
            "version": BUNDLE_FORMAT_VERSION,
            "target_id": tid,
            "exported_at": utc_now(),
            "redacted": bool(redact_pii),
            "files": files_manifest,
        }
        manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
            zf.writestr("manifest.json", manifest_bytes)
            for arc_name, data in archive_entries:
                zf.writestr(arc_name, data)

        zip_bytes = buf.getvalue()
        if len(zip_bytes) > MAX_BUNDLE_BYTES:
            raise ValueError(
                f"Bundle size ({len(zip_bytes)} bytes) exceeds MAX_BUNDLE_BYTES ({MAX_BUNDLE_BYTES})"
            )

    if out_path is not None:
        _atomic_write_bytes(Path(out_path), zip_bytes)

    return zip_bytes, manifest


def _validate_archive_member(info: zipfile.ZipInfo) -> str:
    name = info.filename
    if not name or "\x00" in name or "\\" in name or ":" in name or name.startswith("/"):
        raise ValueError(f"Unsafe bundle member path: {name!r}")
    if info.is_dir() or name.endswith("/"):
        raise ValueError(f"Unexpected directory entry in bundle: {name!r}")

    unix_mode = (info.external_attr >> 16) & 0o170000
    if unix_mode == 0o120000:
        raise ValueError(f"Symlink entry rejected in bundle: {name!r}")
    if unix_mode not in (0, 0o100000):
        raise ValueError(f"Unsupported special file mode in bundle: {name!r}")

    parts = name.split("/")
    if any(part in {"", ".", ".."} or ".." in part for part in parts):
        raise ValueError(f"Path traversal rejected in bundle member: {name!r}")

    if name in {"manifest.json", "erkg.sqlite3"}:
        return name
    if len(parts) == 2 and parts[0] == "raw" and _SAFE_RAW_NAME_RE.match(parts[1]):
        return name
    raise ValueError(f"Unexpected bundle member path: {name!r}")


def _rewrite_db_target_id(db_path: Path, old_id: str, new_id: str) -> None:
    try:
        conn = sqlite3.connect(str(db_path))
    except sqlite3.Error as exc:
        raise ValueError(f"Invalid SQLite database in bundle: {exc}") from exc
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA trusted_schema = OFF;")
        conn.execute("PRAGMA foreign_keys = OFF;")
        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute(
            "SELECT config_json FROM investigations WHERE target_id=?",
            (old_id,),
        ).fetchone()
        if row is not None:
            try:
                cfg = json.loads(row["config_json"] or "{}")
                if isinstance(cfg, dict):
                    cfg["target_id"] = new_id
                cfg_json = json.dumps(cfg, ensure_ascii=False)
            except ValueError:
                cfg_json = row["config_json"]
            conn.execute(
                "UPDATE investigations SET target_id=?, config_json=? WHERE target_id=?",
                (new_id, cfg_json, old_id),
            )

        for table in (
            "artifacts",
            "entities",
            "entity_aliases",
            "claims",
            "contradictions",
            "execution_ledger",
            "hypotheses",
            "iterations",
        ):
            if _table_exists(conn, table):
                conn.execute(
                    f"UPDATE {table} SET investigation_id=? WHERE investigation_id=?",
                    (new_id, old_id),
                )
        if _table_exists(conn, "ai_insights"):
            conn.execute(
                "UPDATE ai_insights SET investigation_id=? WHERE investigation_id=?",
                (new_id, old_id),
            )
        conn.execute("COMMIT")
    except sqlite3.Error as exc:
        raise ValueError(f"Invalid SQLite database in bundle: {exc}") from exc
    finally:
        conn.close()


def _verify_sqlite_integrity(db_path: Path, expected_target_id: str) -> None:
    try:
        conn = sqlite3.connect(str(db_path))
    except sqlite3.Error as exc:
        raise ValueError(f"Invalid SQLite database in bundle: {exc}") from exc
    try:
        conn.execute("PRAGMA trusted_schema = OFF;")
        rows = conn.execute("PRAGMA integrity_check;").fetchall()
        if not rows or len(rows) != 1 or str(rows[0][0]).lower() != "ok":
            raise ValueError(f"SQLite integrity_check failed: {rows}")
        if not _table_exists(conn, "investigations"):
            raise ValueError("Bundle database missing 'investigations' table")
        inv_row = conn.execute(
            "SELECT target_id FROM investigations WHERE target_id=?",
            (expected_target_id,),
        ).fetchone()
        if inv_row is None:
            raise ValueError(f"Bundle database missing investigation {expected_target_id!r}")
    except sqlite3.Error as exc:
        raise ValueError(f"Invalid SQLite database in bundle: {exc}") from exc
    finally:
        conn.close()


def import_case_bundle(
    state_root: Path | str | None,
    source: bytes | Path | str,
    *,
    overwrite: bool = False,
    new_target_id: str | None = None,
    investigations_dir: Path | str | None = None,
) -> dict[str, Any]:
    """Validate and atomically import a ``.osintcase.zip`` bundle into ``investigations/<target_id>/``."""
    if isinstance(source, (bytes, bytearray)):
        raw_zip = bytes(source)
        if len(raw_zip) > MAX_BUNDLE_BYTES:
            raise ValueError(f"Bundle exceeds MAX_BUNDLE_BYTES ({MAX_BUNDLE_BYTES})")
        zip_stream: io.BytesIO | Path = io.BytesIO(raw_zip)
        zip_source_bytes = len(raw_zip)
    else:
        src_path = Path(source).expanduser()
        if not src_path.is_file():
            raise FileNotFoundError(f"Bundle not found: {src_path}")
        zip_source_bytes = src_path.stat().st_size
        if zip_source_bytes > MAX_BUNDLE_BYTES:
            raise ValueError(f"Bundle exceeds MAX_BUNDLE_BYTES ({MAX_BUNDLE_BYTES})")
        zip_stream = src_path

    inv_root = _resolve_import_inv_dir(state_root, investigations_dir=investigations_dir)
    inv_root.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(dir=inv_root, prefix=".import_staging_") as staging_parent:
        staged_case = Path(staging_parent) / "case"
        staged_case.mkdir(parents=True, exist_ok=True)
        (staged_case / "raw").mkdir(exist_ok=True)
        (staged_case / "scratch").mkdir(exist_ok=True)

        try:
            zf = zipfile.ZipFile(zip_stream, mode="r")
        except zipfile.BadZipFile as exc:
            raise ValueError(f"Invalid ZIP archive: {exc}") from exc

        with zf:
            infos = zf.infolist()
            if len(infos) > MAX_BUNDLE_MEMBERS:
                raise ValueError(
                    f"Bundle member count ({len(infos)}) exceeds MAX_BUNDLE_MEMBERS ({MAX_BUNDLE_MEMBERS})"
                )

            seen_names: set[str] = set()
            total_declared = 0
            for info in infos:
                clean_name = _validate_archive_member(info)
                if clean_name in seen_names:
                    raise ValueError(f"Duplicate bundle member rejected: {clean_name!r}")
                seen_names.add(clean_name)

                if info.file_size < 0:
                    raise ValueError(f"Negative file size in bundle: {clean_name!r}")
                total_declared += info.file_size
                if total_declared > MAX_UNCOMPRESSED_BYTES:
                    raise ValueError(
                        f"Declared uncompressed size exceeds MAX_UNCOMPRESSED_BYTES ({MAX_UNCOMPRESSED_BYTES})"
                    )
                if info.compress_size == 0 and info.file_size > 0:
                    raise ValueError(f"Suspicious zero compressed size for non-empty entry: {clean_name!r}")
                if info.compress_size > 0 and (info.file_size / info.compress_size) > MAX_COMPRESSION_RATIO:
                    raise ValueError(
                        f"Compression ratio exceeds MAX_COMPRESSION_RATIO ({MAX_COMPRESSION_RATIO}) for {clean_name!r}"
                    )

            if "manifest.json" not in seen_names or "erkg.sqlite3" not in seen_names:
                raise ValueError("Bundle must contain 'manifest.json' and 'erkg.sqlite3'")

            total_actual = 0
            staged_root_resolved = staged_case.resolve()
            extracted_hashes: dict[str, tuple[str, int]] = {}

            for info in infos:
                dest_file = (staged_case / info.filename).resolve()
                if not dest_file.is_relative_to(staged_root_resolved):
                    raise ValueError(f"Escaping path rejected: {info.filename!r}")
                dest_file.parent.mkdir(parents=True, exist_ok=True)

                hasher = hashlib.sha256()
                entry_actual = 0
                with zf.open(info, mode="r") as src_fh, dest_file.open("wb") as dst_fh:
                    while True:
                        chunk = src_fh.read(_CHUNK_BYTES)
                        if not chunk:
                            break
                        entry_actual += len(chunk)
                        total_actual += len(chunk)
                        if total_actual > MAX_UNCOMPRESSED_BYTES:
                            raise ValueError(
                                f"Streamed uncompressed bytes exceed MAX_UNCOMPRESSED_BYTES ({MAX_UNCOMPRESSED_BYTES})"
                            )
                        if info.compress_size == 0 and entry_actual > 0:
                            raise ValueError(
                                f"Streamed data exceeds zero compressed size for {info.filename!r}"
                            )
                        if info.compress_size > 0 and (entry_actual / info.compress_size) > MAX_COMPRESSION_RATIO:
                            raise ValueError(
                                f"Streamed compression ratio exceeds MAX_COMPRESSION_RATIO for {info.filename!r}"
                            )
                        if zip_source_bytes > 0 and (total_actual / zip_source_bytes) > MAX_COMPRESSION_RATIO:
                            raise ValueError("Overall bundle compression ratio exceeds MAX_COMPRESSION_RATIO")
                        hasher.update(chunk)
                        dst_fh.write(chunk)

                if entry_actual != info.file_size:
                    raise ValueError(
                        f"ZIP header size mismatch for {info.filename!r}: "
                        f"declared={info.file_size}, actual={entry_actual}"
                    )
                if info.filename != "manifest.json":
                    extracted_hashes[info.filename] = (hasher.hexdigest(), entry_actual)

        manifest_path = staged_case / "manifest.json"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ValueError(f"Invalid manifest.json: {exc}") from exc

        if not isinstance(manifest, dict):
            raise ValueError("manifest.json must be a JSON object")
        if manifest.get("format") != BUNDLE_FORMAT:
            raise ValueError(f"Unsupported bundle format: {manifest.get('format')!r}")
        if manifest.get("version") != BUNDLE_FORMAT_VERSION:
            raise ValueError(f"Unsupported bundle version: {manifest.get('version')!r}")

        orig_target_id = _validate_target_id(manifest.get("target_id"))
        final_target_id = (
            _validate_target_id(new_target_id) if new_target_id is not None else orig_target_id
        )

        manifest_files = manifest.get("files")
        if not isinstance(manifest_files, dict) or "erkg.sqlite3" not in manifest_files:
            raise ValueError("manifest.json missing valid 'files' mapping")

        if set(manifest_files.keys()) != set(extracted_hashes.keys()):
            raise ValueError("Bundle contents do not match manifest.json 'files' list")

        for rel_path, meta in manifest_files.items():
            if not isinstance(meta, dict):
                raise ValueError(f"Invalid manifest entry for {rel_path!r}")
            actual_sha, actual_size = extracted_hashes[rel_path]
            if str(meta.get("sha256") or "").lower() != actual_sha:
                raise ValueError(f"SHA-256 verification failed for {rel_path!r}")
            if int(meta.get("size", -1)) != actual_size:
                raise ValueError(f"Byte size verification failed for {rel_path!r}")

        manifest_path.unlink(missing_ok=True)

        staged_db = staged_case / "erkg.sqlite3"
        _verify_sqlite_integrity(staged_db, orig_target_id)
        if final_target_id != orig_target_id:
            _rewrite_db_target_id(staged_db, orig_target_id, final_target_id)
            _verify_sqlite_integrity(staged_db, final_target_id)

        dest_dir = (inv_root / final_target_id).resolve()
        if not dest_dir.is_relative_to(inv_root.resolve()) or dest_dir == inv_root.resolve():
            raise ValueError(f"Resolved destination escapes investigations root: {dest_dir}")

        if dest_dir.exists():
            if not overwrite:
                raise FileExistsError(
                    f"Investigation {final_target_id!r} already exists at {dest_dir}"
                )
            backup_dir = Path(staging_parent) / "prev_backup"
            os.replace(str(dest_dir), str(backup_dir))
            try:
                os.replace(str(staged_case), str(dest_dir))
            except BaseException:
                if backup_dir.exists() and not dest_dir.exists():
                    os.replace(str(backup_dir), str(dest_dir))
                raise
            shutil.rmtree(backup_dir, ignore_errors=True)
        else:
            os.replace(str(staged_case), str(dest_dir))

    return {
        "status": "ok",
        "target_id": final_target_id,
        "imported_from": orig_target_id,
        "redacted": bool(manifest.get("redacted", False)),
        "path": str(dest_dir),
        "file_count": len(manifest_files),
        "manifest": manifest,
    }


__all__ = [
    "BUNDLE_FORMAT",
    "BUNDLE_FORMAT_VERSION",
    "BUNDLE_EXTENSION",
    "MAX_BUNDLE_BYTES",
    "MAX_UNCOMPRESSED_BYTES",
    "MAX_COMPRESSION_RATIO",
    "MAX_BUNDLE_MEMBERS",
    "redact_pii_text",
    "redact_pii_json",
    "export_case_bundle",
    "import_case_bundle",
]
