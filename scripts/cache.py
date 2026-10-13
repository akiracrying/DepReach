"""Content-scoped reachability cache. Legacy unscoped rows are never read."""
import hashlib
import json
import logging
import sqlite3
import time
from pathlib import Path

from scripts.reachability_result import ANALYZER_VERSION

logger = logging.getLogger(__name__)
_db_path = None
CACHE_TTL_SECONDS = 24 * 60 * 60


def make_context(project_digest, references, *, dependency_digests=(), include_tests=False):
    payload = [ANALYZER_VERSION, project_digest, sorted(set(references)),
               sorted(dependency_digests), include_tests]
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def init_cache(db_path="depreach_cache.db"):
    global _db_path
    _db_path = str(Path(db_path).resolve())
    with sqlite3.connect(_db_path) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS reachability_v2 (
            purl TEXT NOT NULL, cve TEXT NOT NULL, context TEXT NOT NULL,
            created REAL NOT NULL, report TEXT NOT NULL,
            PRIMARY KEY (purl, cve, context))""")


def get_cached_reachability(purl, cve, context=None):
    if not _db_path or not context:
        return None
    try:
        with sqlite3.connect(_db_path, timeout=10) as db:
            row = db.execute("SELECT created, report FROM reachability_v2 WHERE purl=? AND cve=? AND context=?",
                             (purl, cve, context)).fetchone()
        if row and time.time() - row[0] < CACHE_TTL_SECONDS:
            return json.loads(row[1])
    except (sqlite3.Error, ValueError):
        logger.warning("Cannot read reachability cache", exc_info=True)
    return None


def cache_reachability(purl, cve, reachability, context=None):
    # Transient download/mapping failures should be retried on the next scan.
    if not _db_path or not context or reachability.get("status") not in {"reachable", "no_path_found"}:
        return
    try:
        with sqlite3.connect(_db_path, timeout=10) as db:
            db.execute("INSERT OR REPLACE INTO reachability_v2 VALUES (?, ?, ?, ?, ?)",
                       (purl, cve, context, time.time(), json.dumps(reachability)))
    except sqlite3.Error:
        logger.warning("Cannot write reachability cache", exc_info=True)
