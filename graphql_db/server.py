import strawberry
from typing import List, Optional
from fastapi import FastAPI
from strawberry.fastapi import GraphQLRouter

# Псевдо-хранилище — замени на SQLite или файл
vuln_cache = {}

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
        return vuln_cache.get(purl, [])

@strawberry.type
class Mutation:
    @strawberry.mutation
    def add_vulnerability(self, vuln: VulnerabilityInput) -> bool:
        vuln_obj = Vulnerability(
            purl=vuln.purl,
            package=vuln.package,
            installed=vuln.installed,
            cve=vuln.cve,
            description=vuln.description,
            severity=vuln.severity,
            score=vuln.score,
            affected_version=vuln.affected_version,
            CWE=vuln.CWE,
            references=vuln.references,
            reachability=Reachability(
                is_reachable=vuln.reachabilityData.is_reachable,
                changed_funcs=vuln.reachabilityData.changed_funcs,
                reachable_funcs=vuln.reachabilityData.reachable_funcs
            )
        )
        vuln_cache.setdefault(vuln.purl, []).append(vuln_obj)
        return True

schema = strawberry.Schema(query=Query, mutation=Mutation)

app = FastAPI()
graphql_app = GraphQLRouter(schema)
app.include_router(graphql_app, prefix="/graphql")
