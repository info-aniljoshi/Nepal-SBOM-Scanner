import json
import re
import xml.etree.ElementTree as ET
import logging
from pathlib import Path
from typing import List, Dict, Set, Type, Optional
from core.models import Package

logger = logging.getLogger("nepal-sbom-parsers")

class BaseParser:
    ecosystem: str = "unknown"

    def parse(self, file_path: Path) -> List[Package]:
        raise NotImplementedError

class PackageJsonParser(BaseParser):
    ecosystem = "npm"

    def parse(self, file_path: Path) -> List[Package]:
        packages: List[Package] = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            deps: Dict[str, str] = {}
            deps.update(data.get("dependencies", {}))
            deps.update(data.get("devDependencies", {}))

            for name, version in deps.items():
                clean_version = str(version).lstrip("^~>=<!")
                packages.append(Package(
                    name=name,
                    version=clean_version,
                    ecosystem=self.ecosystem,
                    purl=f"pkg:npm/{name}@{clean_version}"
                ))
        except Exception as e:
            logger.error(f"Failed to parse package.json at {file_path}: {e}")
        return packages

class PackageLockParser(BaseParser):
    ecosystem = "npm"

    def parse(self, file_path: Path) -> List[Package]:
        packages: List[Package] = []
        try:
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
        except Exception as e:
            logger.error(f"Failed to parse package-lock.json at {file_path}: {e}")
        return packages

class RequirementsTxtParser(BaseParser):
    ecosystem = "PyPI"

    def parse(self, file_path: Path) -> List[Package]:
        packages: List[Package] = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith(('#', '-')):
                        continue
                    match = re.match(r'^([a-zA-Z0-9_.-]+)\s*[=<>~!]+\s*([0-9a-zA-Z_.+-]+)', line)
                    if match:
                        name, version = match.groups()
                        packages.append(Package(
                            name=name,
                            version=version,
                            ecosystem=self.ecosystem,
                            purl=f"pkg:pypi/{name}@{version}"
                        ))
        except Exception as e:
            logger.error(f"Failed to parse requirements.txt at {file_path}: {e}")
        return packages

class PyProjectParser(BaseParser):
    ecosystem = "PyPI"

    def parse(self, file_path: Path) -> List[Package]:
        packages: List[Package] = []
        try:
            try:
                import tomllib
            except ImportError:
                # Expert Note: Fallback to tomli for older Python versions
                import tomli as tomllib # type: ignore

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
        except Exception as e:
            logger.error(f"Failed to parse pyproject.toml at {file_path}: {e}")
        return packages

class PipfileLockParser(BaseParser):
    ecosystem = "PyPI"

    def parse(self, file_path: Path) -> List[Package]:
        packages: List[Package] = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            default = data.get("default", {})
            for name, info in default.items():
                if isinstance(info, dict) and "version" in info:
                    version = str(info["version"]).lstrip("=")
                    packages.append(Package(
                        name=name,
                        version=version,
                        ecosystem=self.ecosystem,
                        purl=f"pkg:pypi/{name}@{version}"
                    ))
        except Exception as e:
            logger.error(f"Failed to parse Pipfile.lock at {file_path}: {e}")
        return packages

class PomXmlParser(BaseParser):
    ecosystem = "Maven"

    def parse(self, file_path: Path) -> List[Package]:
        packages: List[Package] = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            ns = {'m': 'http://maven.apache.org/POM/4.0.0'}

            for dep in root.findall('.//m:dependency', ns):
                group = dep.find('m:groupId', ns)
                artifact = dep.find('m:artifactId', ns)
                version = dep.find('m:version', ns)

                if group is not None and artifact is not None:
                    g, a = group.text, artifact.text
                    v = version.text if version is not None else "0.0.0"
                    if v and not str(v).startswith("$"):
                        packages.append(Package(
                            name=f"{g}:{a}",
                            version=str(v),
                            ecosystem=self.ecosystem,
                            purl=f"pkg:maven/{g}/{a}@{v}"
                        ))
        except Exception as e:
            logger.error(f"Failed to parse pom.xml at {file_path}: {e}")
        return packages

class GoModParser(BaseParser):
    ecosystem = "Go"

    def parse(self, file_path: Path) -> List[Package]:
        packages: List[Package] = []
        try:
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
                            mod_path, version = parts[0], parts[1]
                            packages.append(Package(
                                name=mod_path,
                                version=version.lstrip("v"),
                                ecosystem=self.ecosystem,
                                purl=f"pkg:golang/{mod_path}@{version}"
                            ))
        except Exception as e:
            logger.error(f"Failed to parse go.mod at {file_path}: {e}")
        return packages

PARSERS: Dict[str, Type[BaseParser]] = {
    "package.json": PackageJsonParser,
    "package-lock.json": PackageLockParser,
    "requirements.txt": RequirementsTxtParser,
    "pyproject.toml": PyProjectParser,
    "Pipfile.lock": PipfileLockParser,
    "pom.xml": PomXmlParser,
    "go.mod": GoModParser,
}

def scan_directory(directory: str) -> List[Package]:
    """Expert Note: Refactored to use Pathlib for better Windows/Unix compatibility and security"""
    all_packages: List[Package] = []
    seen: Set[str] = set()
    base_path = Path(directory).resolve()

    # Skip directories that typically contain noise or generated artifacts
    skip_dirs = {
        'node_modules', 'venv', '.venv', '__pycache__', 
        'target', 'build', '.git', '.pytest_cache', 'dist'
    }

    for path in base_path.rglob("*"):
        # Check if any parent directory should be skipped
        if any(part in skip_dirs for part in path.parts):
            continue
            
        if path.is_file() and path.name in PARSERS:
            try:
                parser_cls = PARSERS[path.name]
                pkgs = parser_cls().parse(path)
                for pkg in pkgs:
                    key = f"{pkg.ecosystem}:{pkg.name}:{pkg.version}"
                    if key not in seen:
                        seen.add(key)
                        all_packages.append(pkg)
            except Exception as e:
                logger.error(f"Error invoking parser for {path}: {e}")

    return all_packages
