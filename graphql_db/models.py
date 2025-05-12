from sqlalchemy import create_engine, Column, String, Float, Integer, Table, ForeignKey
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from sqlalchemy.types import JSON

Base = declarative_base()

class VulnerabilityModel(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True)
    purl = Column(String)
    package = Column(String)
    installed = Column(String)
    cve = Column(String)
    description = Column(String)
    severity = Column(String)
    score = Column(Float, nullable=True)
    affected_version = Column(String, nullable=True)
    cwe = Column(String, nullable=True)
    references = Column(JSON)
    reachability = Column(JSON)
