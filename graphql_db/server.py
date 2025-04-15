import strawberry
from typing import List, Optional
from fastapi import FastAPI
from strawberry.fastapi import GraphQLRouter
from models import VulnerabilityModel, Base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

engine = create_engine("sqlite:///vulns.db", connect_args={"check_same_thread": False})
Base.metadata.create_all(engine)
SessionLocal = sessionmaker(bind=engine)


@strawberry.input
class ReachabilityInput:
    is_reachable: str
    changed_funcs: Optional[List[str]] = None
    reachable_funcs: Optional[List[str]] = None

@strawberry.type
class Reachability:
    is_reachable: str
    changed_funcs: Optional[List[str]] = None
    reachable_funcs: Optional[List[str]] = None

@strawberry.input
class VulnerabilityInput:
    purl: str
    package: str
    installed: str
    cve: str
    description: str
    severity: str
    score: Optional[float]
    affectedVersion: Optional[str]
    CWE: Optional[str]
    references: List[str]
    reachabilityData: ReachabilityInput

@strawberry.type
class Vulnerability:
    purl: str
    package: str
    installed: str
    cve: str
    description: str
    severity: str
    score: Optional[float]
    affectedVersion: Optional[str]
    CWE: Optional[str]
    references: List[str]
    reachability: Reachability

@strawberry.type
class Query:
    @strawberry.field
    def get_vulns_by_purl(self, purl: str) -> List[Vulnerability]:
        db = SessionLocal()
        try:
            vulns = db.query(VulnerabilityModel).filter_by(purl=purl).all()
            return [
                Vulnerability(
                    purl=v.purl,
                    package=v.package,
                    installed=v.installed,
                    cve=v.cve,
                    description=v.description,
                    severity=v.severity,
                    score=v.score,
                    affectedVersion=v.affected_version,
                    CWE=v.cwe,
                    references=v.references,
                    reachability=Reachability(
                        is_reachable=v.reachability.get("is_reachable", "Unknown"),
                        changed_funcs=v.reachability.get("changed_funcs"),
                        reachable_funcs=v.reachability.get("reachable_funcs")
                    )
                ) for v in vulns
            ]
        finally:
            db.close()


@strawberry.type
class Mutation:
    @strawberry.mutation
    def add_vulnerability(self, vuln: VulnerabilityInput) -> bool:
        db = SessionLocal()
        try:
            vuln_obj = VulnerabilityModel(
                purl=vuln.purl,
                package=vuln.package,
                installed=vuln.installed,
                cve=vuln.cve,
                description=vuln.description,
                severity=vuln.severity,
                score=vuln.score,
                affected_version=vuln.affectedVersion,
                cwe=vuln.CWE,
                references=vuln.references,
                reachability={
                    "is_reachable": vuln.reachabilityData.is_reachable,
                    "changed_funcs": vuln.reachabilityData.changed_funcs,
                    "reachable_funcs": vuln.reachabilityData.reachable_funcs
                }
            )
            db.add(vuln_obj)
            db.commit()
            return True
        except Exception as e:
            print(f"[error] DB insert failed: {e}")
            db.rollback()
            return False
        finally:
            db.close()


schema = strawberry.Schema(query=Query, mutation=Mutation)

app = FastAPI()
graphql_app = GraphQLRouter(schema)
app.include_router(graphql_app, prefix="/graphql")
