import json
import os
import re
import xml.etree.ElementTree as ET
from typing import List
from core.models import Package

class BaseParser:
    ecosystem: str = "unknown"

    def parse(self, file_path: str) -> List[Package]:
        raise NotImplementedError

class PackageJsonParser(BaseParser):
    ecosystem = "npm"

    def parse(self, file_path: str) -> List[Package]:
        packages = []
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        deps = {}
        deps.update(data.get("dependencies", {}))
        deps.update(data.get("devDependencies", {}))

        for name, version in deps.items():
            clean_version = version.lstrip("^~>=<!")
            packages.append(Package(
                name=name,
                version=clean_version,
                ecosystem=self.ecosystem,
                purl=f"pkg:npm/{name}@{clean_version}"
            ))
        return packages

class PackageLockParser(BaseParser):
    ecosystem = "npm"

    def parse(self, file_path: str) -> List[Package]:
        packages = []
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        lockfile_version = data.get("lockfileVersion", 1)

        if lockfile_version in (2, 3):
            pkgs = data.get("packages", {})
            for path, info in pkgs.items():
                if path == "" or not info.get("version"):
                    continue
                name = path.split("node_modules/")[-1]
                if not name or name.startswith("."):
                    continue
                packages.append(Package(
                    name=name,
                    version=info["version"],
                    ecosystem=self.ecosystem,
                    purl=f"pkg:npm/{name}@{info['version']}"
                ))
        elif lockfile_version == 1:
            deps = data.get("dependencies", {})
            for name, info in deps.items():
                if isinstance(info, dict) and "version" in info:
                    packages.append(Package(
                        name=name,
                        version=info["version"],
                        ecosystem=self.ecosystem,
                        purl=f"pkg:npm/{name}@{info['version']}"
                    ))
        return packages

class RequirementsTxtParser(BaseParser):
    ecosystem = "PyPI"

    def parse(self, file_path: str) -> List[Package]:
        packages = []
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('-'):
                    continue
                # FIXED: Put hyphen at end of character class, no escaping needed
                match = re.match(r'^([a-zA-Z0-9_.-]+)\s*[=<>~!]+\s*([0-9a-zA-Z_.+-]+)', line)
                if match:
                    name, version = match.groups()
                    packages.append(Package(
                        name=name,
                        version=version,
                        ecosystem=self.ecosystem,
                        purl=f"pkg:pypi/{name}@{version}"
                    ))
        return packages

class PyProjectParser(BaseParser):
    ecosystem = "PyPI"

    def parse(self, file_path: str) -> List[Package]:
        packages = []
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib

        with open(file_path, 'rb') as f:
            data = tomllib.load(f)

        deps = data.get("project", {}).get("dependencies", [])
        for dep in deps:
            match = re.match(r'^([a-zA-Z0-9_.-]+)\s*[=<>~!]+\s*([0-9a-zA-Z_.+-]+)', dep)
            if match:
                name, version = match.groups()
                packages.append(Package(
                    name=name,
                    version=version,
                    ecosystem=self.ecosystem,
                    purl=f"pkg:pypi/{name}@{version}"
                ))
        return packages

class PipfileLockParser(BaseParser):
    ecosystem = "PyPI"

    def parse(self, file_path: str) -> List[Package]:
        packages = []
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        default = data.get("default", {})
        for name, info in default.items():
            if isinstance(info, dict) and "version" in info:
                version = info["version"].lstrip("=")  # Remove leading = if present
                packages.append(Package(
                    name=name,
                    version=version,
                    ecosystem=self.ecosystem,
                    purl=f"pkg:pypi/{name}@{version}"
                ))
        return packages

class PomXmlParser(BaseParser):
    ecosystem = "Maven"

    def parse(self, file_path: str) -> List[Package]:
        packages = []
        tree = ET.parse(file_path)
        root = tree.getroot()
        ns = {'m': 'http://maven.apache.org/POM/4.0.0'}

        for dep in root.findall('.//m:dependency', ns):
            group = dep.find('m:groupId', ns)
            artifact = dep.find('m:artifactId', ns)
            version = dep.find('m:version', ns)

            if group is not None and artifact is not None:
                g = group.text
                a = artifact.text
                v = version.text if version is not None else "0.0.0"
                if v and not v.startswith("$"):
                    packages.append(Package(
                        name=f"{g}:{a}",
                        version=v,
                        ecosystem=self.ecosystem,
                        purl=f"pkg:maven/{g}/{a}@{v}"
                    ))
        return packages

class GoModParser(BaseParser):
    ecosystem = "Go"

    def parse(self, file_path: str) -> List[Package]:
        packages = []
        with open(file_path, 'r', encoding='utf-8') as f:
            in_require = False
            for line in f:
                line = line.strip()
                if line.startswith("require ("):
                    in_require = True
                    continue
                if in_require and line == ")":
                    in_require = False
                    continue
                if in_require or line.startswith("require "):
                    parts = line.replace("require ", "").strip().split()
                    if len(parts) >= 2:
                        mod_path = parts[0]
                        version = parts[1]
                        packages.append(Package(
                            name=mod_path,
                            version=version.lstrip("v"),
                            ecosystem=self.ecosystem,
                            purl=f"pkg:golang/{mod_path}@{version}"
                        ))
        return packages

PARSERS = {
    "package.json": PackageJsonParser,
    "package-lock.json": PackageLockParser,
    "requirements.txt": RequirementsTxtParser,
    "pyproject.toml": PyProjectParser,
    "Pipfile.lock": PipfileLockParser,
    "pom.xml": PomXmlParser,
    "go.mod": GoModParser,
}

def scan_directory(directory: str) -> List[Package]:
    all_packages = []
    seen = set()

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in ('node_modules', 'venv', '.venv', '__pycache__', 'target', 'build', '.git')]

        for filename in files:
            if filename in PARSERS:
                filepath = os.path.join(root, filename)
                try:
                    parser = PARSERS[filename]()
                    pkgs = parser.parse(filepath)
                    for pkg in pkgs:
                        key = f"{pkg.ecosystem}:{pkg.name}:{pkg.version}"
                        if key not in seen:
                            seen.add(key)
                            all_packages.append(pkg)
                except Exception as e:
                    print(f"Error parsing {filepath}: {e}")

    return all_packages
