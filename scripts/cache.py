"""Direct SQLite cache for reachability results — no server required."""

from sqlalchemy import create_engine, Column, String, Float, Integer
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.types import JSON

Base = declarative_base()


class CachedVulnerability(Base):
    __tablename__ = "cached_vulnerabilities"

    id = Column(Integer, primary_key=True)
    purl = Column(String, index=True)
    cve = Column(String, index=True)
    reachability = Column(JSON)


_engine = None
_Session = None


def init_cache(db_path: str = "depreach_cache.db"):
    global _engine, _Session
    _engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(_engine)
    _Session = sessionmaker(bind=_engine)


def get_cached_reachability(purl: str, cve: str) -> dict | None:
    if not _Session:
        return None
    db = _Session()
    try:
        row = (
            db.query(CachedVulnerability)
            .filter_by(purl=purl, cve=cve)
            .first()
        )
        return row.reachability if row else None
    finally:
        db.close()


def cache_reachability(purl: str, cve: str, reachability: dict):
    if not _Session:
        return
    db = _Session()
    try:
        existing = (
            db.query(CachedVulnerability)
            .filter_by(purl=purl, cve=cve)
            .first()
        )
        if existing:
            existing.reachability = reachability
        else:
            db.add(CachedVulnerability(purl=purl, cve=cve, reachability=reachability))
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()
