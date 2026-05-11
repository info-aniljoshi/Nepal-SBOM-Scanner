import os
import tempfile
import json
from core.parsers import (
    PackageJsonParser, RequirementsTxtParser, PomXmlParser,
    GoModParser, PipfileLockParser, scan_directory
)

def test_package_json_parser():
    with tempfile.NamedTemporaryFile(mode='w', suffix='package.json', delete=False) as f:
        json.dump({
            "name": "test-project",
            "dependencies": {
                "lodash": "^4.17.21",
                "express": "~4.18.0"
            },
            "devDependencies": {
                "jest": ">=29.0.0"
            }
        }, f)
        path = f.name

    parser = PackageJsonParser()
    pkgs = parser.parse(path)

    assert len(pkgs) == 3
    names = [p.name for p in pkgs]
    assert "lodash" in names
    assert "express" in names
    assert "jest" in names

    os.unlink(path)

def test_requirements_txt_parser():
    with tempfile.NamedTemporaryFile(mode='w', suffix='requirements.txt', delete=False) as f:
        f.write("requests==2.32.3\n")
        f.write("fastapi>=0.111.0\n")
        f.write("# comment\n")
        f.write("-e .\n")
        path = f.name

    parser = RequirementsTxtParser()
    pkgs = parser.parse(path)

    assert len(pkgs) == 2
    names = [p.name for p in pkgs]
    assert "requests" in names
    assert "fastapi" in names

    os.unlink(path)

def test_pom_xml_parser():
    with tempfile.NamedTemporaryFile(mode='w', suffix='pom.xml', delete=False) as f:
        f.write("""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>5.3.21</version>
        </dependency>
        <dependency>
            <groupId>com.google.guava</groupId>
            <artifactId>guava</artifactId>
            <version>31.1-jre</version>
        </dependency>
    </dependencies>
</project>""")
        path = f.name

    parser = PomXmlParser()
    pkgs = parser.parse(path)

    assert len(pkgs) == 2
    names = [p.name for p in pkgs]
    assert "org.springframework:spring-core" in names
    assert "com.google.guava:guava" in names

    os.unlink(path)

def test_go_mod_parser():
    with tempfile.NamedTemporaryFile(mode='w', suffix='go.mod', delete=False) as f:
        f.write("""module example.com/test

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/stretchr/testify v1.8.4
)
""")
        path = f.name

    parser = GoModParser()
    pkgs = parser.parse(path)

    assert len(pkgs) == 2
    names = [p.name for p in pkgs]
    assert "github.com/gin-gonic/gin" in names
    assert "github.com/stretchr/testify" in names

    os.unlink(path)

def test_pipfile_lock_parser():
    with tempfile.NamedTemporaryFile(mode='w', suffix='Pipfile.lock', delete=False) as f:
        json.dump({
            "default": {
                "requests": {"version": "==2.32.3"},
                "fastapi": {"version": ">=0.111.0"}
            },
            "develop": {
                "pytest": {"version": "==8.0.0"}
            }
        }, f)
        path = f.name

    parser = PipfileLockParser()
    pkgs = parser.parse(path)

    assert len(pkgs) == 2  # Only default, not develop
    names = [p.name for p in pkgs]
    assert "requests" in names
    assert "fastapi" in names

    os.unlink(path)

def test_scan_directory_mixed():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create package.json
        with open(os.path.join(tmpdir, "package.json"), 'w') as f:
            json.dump({"dependencies": {"lodash": "^4.17.21"}}, f)
        # Create requirements.txt
        with open(os.path.join(tmpdir, "requirements.txt"), 'w') as f:
            f.write("requests==2.32.3\n")
        # Create a nested go.mod
        subdir = os.path.join(tmpdir, "backend")
        os.makedirs(subdir)
        with open(os.path.join(subdir, "go.mod"), 'w') as f:
            f.write("module backend\ngo 1.21\nrequire github.com/gin-gonic/gin v1.9.1\n")

        pkgs = scan_directory(tmpdir)
        names = [p.name for p in pkgs]

        assert "lodash" in names
        assert "requests" in names
        assert "github.com/gin-gonic/gin" in names
        assert len(pkgs) == 3

if __name__ == "__main__":
    test_package_json_parser()
    test_requirements_txt_parser()
    test_pom_xml_parser()
    test_go_mod_parser()
    test_pipfile_lock_parser()
    test_scan_directory_mixed()
    print("✅ All 6 parser tests passed!")
