"""Tests for community rule packs (:mod:`portcullis.rules.packs`)."""

from __future__ import annotations

import textwrap
from pathlib import Path

from portcullis.model import (
    Exposure,
    ImageRef,
    PortMapping,
    Service,
    Severity,
    Stack,
)
from portcullis.rules import RuleContext, run_all
from portcullis.rules.packs import evaluate, load_packs


def write_pack(directory: Path, content: str, name: str = "pack.yaml") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")
    return directory


def service(name: str = "app", image: str = "app:1.0", **kwargs) -> Service:
    return Service(name=name, image=ImageRef.parse(image), **kwargs)


def ctx(*services: Service, exposures: dict | None = None) -> RuleContext:
    stack = Stack(root=Path("/x"), services={s.name: s for s in services})
    return RuleContext(stack=stack, exposures=exposures or {})


class TestLoading:
    def test_valid_rule_loads(self, tmp_path: Path) -> None:
        d = write_pack(tmp_path / "p", """
            pack: {name: mypack, version: 1.0.0}
            rules:
              - id: MYPACK-001
                title: "t"
                severity: high
                match: {image: "*/prometheus"}
                description: d
        """)
        rules, warnings = load_packs([d])
        assert warnings == []
        assert len(rules) == 1
        assert rules[0].id == "MYPACK-001"
        assert rules[0].severity == Severity.HIGH
        assert rules[0].pack_name == "mypack"

    def test_rule_without_match_is_rejected(self, tmp_path: Path) -> None:
        d = write_pack(tmp_path / "p", """
            rules:
              - id: X-1
                title: t
                match: {}
        """)
        rules, warnings = load_packs([d])
        assert rules == []
        assert any("no match conditions" in w for w in warnings)

    def test_unknown_matcher_is_rejected(self, tmp_path: Path) -> None:
        d = write_pack(tmp_path / "p", """
            rules:
              - id: X-1
                match: {imagge: "*/x"}
        """)
        rules, warnings = load_packs([d])
        assert rules == []
        assert any("unknown matcher" in w for w in warnings)

    def test_reserved_pc_prefix_is_rejected(self, tmp_path: Path) -> None:
        d = write_pack(tmp_path / "p", """
            rules:
              - id: PC-001
                match: {privileged: true}
        """)
        rules, warnings = load_packs([d])
        assert rules == []
        assert any("reserved PC- prefix" in w for w in warnings)

    def test_duplicate_ids_dropped(self, tmp_path: Path) -> None:
        write_pack(tmp_path / "p", """
            rules:
              - {id: DUP-1, match: {privileged: true}}
        """, name="a.yaml")
        write_pack(tmp_path / "p", """
            rules:
              - {id: DUP-1, match: {privileged: true}}
        """, name="b.yaml")
        rules, warnings = load_packs([tmp_path / "p"])
        assert len(rules) == 1
        assert any("duplicate rule id" in w for w in warnings)

    def test_malformed_yaml_warns_without_raising(self, tmp_path: Path) -> None:
        d = write_pack(tmp_path / "p", "rules: [unclosed\n")
        rules, warnings = load_packs([d])
        assert rules == []
        assert warnings


class TestMatchers:
    def _fire(self, match: str, svc: Service, exposures: dict | None = None) -> bool:
        pack = f"rules:\n  - id: T-1\n    severity: low\n    match:\n{match}\n    title: t"
        import tempfile
        d = Path(tempfile.mkdtemp())
        (d / "p.yaml").write_text(pack, encoding="utf-8")
        rules, warnings = load_packs([d])
        assert warnings == [], warnings
        return bool(evaluate(rules, ctx(svc, exposures=exposures)))

    def test_image_glob(self) -> None:
        assert self._fire('      image: "*/redis"', service(image="library/redis:7"))
        assert not self._fire('      image: "*/redis"', service(image="nginx:1"))

    def test_published_port(self) -> None:
        svc = service(ports=[PortMapping(container_port=80, host_port=9090)])
        assert self._fire("      published_port: 9090", svc)
        assert not self._fire("      published_port: 9091", svc)

    def test_privileged(self) -> None:
        assert self._fire("      privileged: true", service(privileged=True))
        assert not self._fire("      privileged: true", service(privileged=False))

    def test_cap_add_prefix_insensitive(self) -> None:
        assert self._fire("      cap_add: [SYS_ADMIN]", service(cap_add=["CAP_SYS_ADMIN"]))

    def test_env_present(self) -> None:
        assert self._fire("      env_present: [API_TOKEN]",
                          service(environment={"API_TOKEN": "x"}))
        assert not self._fire("      env_present: [API_TOKEN]", service())

    def test_network_mode(self) -> None:
        assert self._fire("      network_mode: host", service(network_mode="host"))

    def test_exposure_threshold(self) -> None:
        svc = service("web")
        assert self._fire("      exposure: LAN", svc, exposures={"web": Exposure.INTERNET})
        assert not self._fire("      exposure: LAN", svc, exposures={"web": Exposure.HOST})

    def test_all_conditions_anded(self) -> None:
        svc = service(image="library/redis:7", privileged=True)
        assert self._fire('      image: "*/redis"\n      privileged: true', svc)
        # privileged mismatch -> no fire even though image matches
        svc2 = service(image="library/redis:7", privileged=False)
        assert not self._fire('      image: "*/redis"\n      privileged: true', svc2)


class TestEvaluation:
    def test_finding_fields_and_placeholder(self, tmp_path: Path) -> None:
        d = write_pack(tmp_path / "p", """
            pack: {name: mypack}
            rules:
              - id: MYPACK-001
                title: "'{service}' runs {image}"
                severity: medium
                match: {image: "*/redis"}
                description: "'{service}' issue"
                risk: r
                remediation: fix
        """)
        rules, _ = load_packs([d])
        svc = service("cache", image="library/redis:7")
        findings = evaluate(rules, ctx(svc, exposures={"cache": Exposure.LAN}))
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "MYPACK-001"
        assert f.title == "'cache' runs library/redis:7"
        assert f.description == "'cache' issue"
        assert f.service == "cache"
        assert f.severity == Severity.MEDIUM
        assert f.source == "pack:mypack"

    def test_run_all_includes_pack_findings(self, tmp_path: Path) -> None:
        d = write_pack(tmp_path / "p", """
            rules:
              - id: PACK-1
                severity: low
                match: {privileged: true}
                title: t
        """)
        rules, _ = load_packs([d])
        context = ctx(service("bad", privileged=True))
        context.packs = rules
        findings = run_all(context)
        assert any(f.rule_id == "PACK-1" for f in findings)

    def test_no_packs_no_pack_findings(self) -> None:
        findings = run_all(ctx(service("ok")))
        assert all(not f.rule_id.startswith("PACK") for f in findings)
