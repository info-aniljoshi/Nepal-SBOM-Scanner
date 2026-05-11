import json
from datetime import datetime

def generate_spdx(scan_report: dict) -> str:
    """Simple SPDX 2.3 JSON generator for compliance export"""
    creation_info = {
        "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "creators": ["Organization: Nepal SBOM Scanner"],
        "licenseListVersion": "3.20"
    }
    
    packages = []
    relationships = []
    
    for i, pkg in enumerate(scan_report.get("packages", [])):
        pkg_id = f"SPDXRef-Package-{i}"
        packages.append({
            "name": pkg.get("name"),
            "SPDXID": pkg_id,
            "versionInfo": pkg.get("version"),
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": f"pkg:generic/{pkg.get('name')}@{pkg.get('version')}"
                }
            ]
        })
        relationships.append({
            "spdxElementId": "SPDXRef-Document",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": pkg_id
        })

    spdx_doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-Document",
        "name": f"SBOM-{scan_report.get('project_name', 'project')}",
        "documentNamespace": f"https://nepal-sbom.ai/spdx/{scan_report.get('project_name', 'project')}-{datetime.utcnow().timestamp()}",
        "creationInfo": creation_info,
        "packages": packages,
        "relationships": relationships
    }
    
    return json.dumps(spdx_doc, indent=2)
