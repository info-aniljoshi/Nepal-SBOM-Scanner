#!/usr/bin/env python3
import argparse
import json
import sys
import os
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scanner import generate_report

def main():
    parser = argparse.ArgumentParser(description="Nepal SBOM Scanner")
    parser.add_argument("path", help="Path to project directory")
    parser.add_argument("--name", help="Project name", default=None)
    parser.add_argument("--format", choices=["json", "spdx", "summary"], default="summary")
    parser.add_argument("--output", "-o", help="Output file path")

    args = parser.parse_args()

    if not os.path.isdir(args.path):
        print(f"Error: {args.path} is not a valid directory")
        sys.exit(1)

    print(f"🔍 Scanning {args.path}...")
    report = asyncio.run(generate_report(args.path, args.name))

    if args.format == "summary":
        print(f"\n📦 Project: {report.project_name}")
        print(f"   Total Packages: {report.total_packages}")
        print(f"   🔴 Critical: {report.critical_count}")
        print(f"   🟠 High: {report.high_count}")
        print(f"   ⚠️  Total Vulnerabilities: {len(report.vulnerabilities)}")

        if report.vulnerabilities:
            print("\n🚨 Top Vulnerabilities:")
            for v in report.vulnerabilities[:10]:
                icon = "🔴" if v.severity == "CRITICAL" else "🟠" if v.severity == "HIGH" else "🟡"
                print(f"   {icon} {v.id} ({v.severity}): {v.summary[:80]}...")

    elif args.format == "json":
        output = json.dumps(report.model_dump(), indent=2, default=str)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"✅ Report saved to {args.output}")
        else:
            print(output)

    elif args.format == "spdx":
        spdx = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": report.project_name,
            "documentNamespace": f"https://nepalsbom.com/{report.project_name}",
            "packages": []
        }
        for i, pkg in enumerate(report.packages):
            spdx["packages"].append({
                "SPDXID": f"SPDXRef-Package-{i}",
                "name": pkg.name,
                "versionInfo": pkg.version,
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": "NOASSERTION",
                "externalRefs": [{
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": pkg.purl
                }]
            })
        output = json.dumps(spdx, indent=2)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"✅ SPDX report saved to {args.output}")
        else:
            print(output)

if __name__ == "__main__":
    main()
