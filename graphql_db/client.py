from gql import gql, Client
from gql.transport.aiohttp import AIOHTTPTransport
import asyncio
import logging

from gql.transport.exceptions import TransportQueryError
logging.getLogger("gql.transport.aiohttp").setLevel(logging.CRITICAL)

transport = AIOHTTPTransport(url="http://localhost:5555/graphql")
client = Client(transport=transport, fetch_schema_from_transport=True)

async def query_reachability_by_purl(purl: str):
    query = gql("""
        query GetVulnsByPurl($purl: String!) {
            getVulnsByPurl(purl: $purl) {
                cve
                description
                severity
                reachability {
                    isReachable
                    changedFuncs
                    reachableFuncs
                }
            }
        }
    """)
    result = await client.execute_async(query, variable_values={"purl": purl})
    return result["getVulnsByPurl"]

async def add_vuln_to_graphql(vuln: dict):
    try:
        reach_data = vuln["reachability"]
        if isinstance(reach_data, dict) and "is_reachable" in reach_data:
            reach_info = reach_data
        else:
            reach_info = list(reach_data.values())[0]

        mutation = gql("""
            mutation AddVuln($vuln: VulnerabilityInput!) {
                addVulnerability(vuln: $vuln)
            }
        """)

        payload = {
            "vuln": {
                "purl": vuln["purl"],
                "package": vuln["package"],
                "installed": vuln["installed_version"],
                "cve": vuln["cve"],
                "description": vuln["description"],
                "severity": vuln["severity"],
                "score": vuln.get("score"),
                "affectedVersion": vuln.get("affected_version"),
                "CWE": vuln.get("CWE"),
                "references": vuln.get("references", []),
                "reachabilityData": {
                    "isReachable": str(reach_info.get("is_reachable", "Unknown")),
                    "changedFuncs": reach_info.get("changed_funcs", []),
                    "reachableFuncs": reach_info.get("reachable_funcs", [])
                }
            }
        }

        await client.execute_async(mutation, variable_values=payload)
        print(f"[graphql] Added new vulnerability info for {vuln['purl']} (CVE: {vuln['cve']})")

    except TimeoutError:
        print(f"[error] GraphQL request timed out for {vuln['purl']} (CVE: {vuln['cve']})")

    except TransportQueryError as e:
        print(f"[error] GraphQL transport error while adding {vuln['purl']} (CVE: {vuln['cve']}): {e}")

    except Exception as e:
        print(f"[error] Unexpected error while adding {vuln['purl']} (CVE: {vuln['cve']}): {e}")