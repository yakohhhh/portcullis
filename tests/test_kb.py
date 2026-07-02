"""Tests for the knowledge base (:mod:`portcullis.kb`).

Covers loading the bundled entries, image pattern matching (case
insensitivity, full repository vs last name component), graceful handling of
broken or incomplete YAML files, and the exposure recommendation logic.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from portcullis.kb import AppInfo, KnowledgeBase
from portcullis.model import Exposure, ImageRef


def make_app(
    recommendation: str = "proxy-only",
    patterns: tuple[str, ...] = ("example/app",),
) -> AppInfo:
    return AppInfo(
        id="example",
        name="Example",
        category="other",
        sensitivity="medium",
        image_patterns=patterns,
        exposure_recommendation=recommendation,
    )


class TestLoadDefault:
    def test_bundled_kb_contains_at_least_one_app(self) -> None:
        kb = KnowledgeBase.load_default()
        assert len(kb) >= 1  # no exact count: the KB grows with contributions

    def test_matches_vaultwarden_image(self) -> None:
        kb = KnowledgeBase.load_default()
        app = kb.match(ImageRef.parse("vaultwarden/server:1.30"))
        assert app is not None
        assert app.id == "vaultwarden"

    def test_matches_vaultwarden_behind_a_registry_prefix(self) -> None:
        kb = KnowledgeBase.load_default()
        app = kb.match(ImageRef.parse("ghcr.io/dani-garcia/vaultwarden:1.30"))
        assert app is not None
        assert app.id == "vaultwarden"

    def test_unknown_image_returns_none(self) -> None:
        kb = KnowledgeBase.load_default()
        assert kb.match(ImageRef.parse("acme/definitely-not-in-the-kb:1.0")) is None


class TestPatternMatching:
    def test_matching_is_case_insensitive_on_the_image(self) -> None:
        app = make_app(patterns=("vaultwarden/server",))
        assert app.matches(ImageRef.parse("VaultWarden/Server:1.30")) is True

    def test_matching_is_case_insensitive_on_the_pattern(self) -> None:
        app = make_app(patterns=("VAULTWARDEN/SERVER",))
        assert app.matches(ImageRef.parse("vaultwarden/server:1.30")) is True

    def test_pattern_matches_the_full_repository(self) -> None:
        app = make_app(patterns=("vaultwarden/server",))
        assert app.matches(ImageRef.parse("vaultwarden/server:1.30")) is True

    def test_pattern_matches_the_last_name_component(self) -> None:
        # "grafana" is not the full repository, but it is its last component.
        app = make_app(patterns=("grafana",))
        assert app.matches(ImageRef.parse("docker.io/grafana/grafana:10.4")) is True

    def test_unrelated_image_does_not_match(self) -> None:
        app = make_app(patterns=("grafana",))
        assert app.matches(ImageRef.parse("library/nginx:1.27")) is False


class TestLoadCustomDirectory:
    VALID_ENTRY = (
        "id: valid\n"
        "name: Valid App\n"
        "category: other\n"
        "sensitivity: low\n"
        "images:\n"
        "  - valid/app\n"
        "exposure: lan\n"
    )

    def test_broken_yaml_file_is_skipped_without_raising(self, tmp_path: Path) -> None:
        (tmp_path / "broken.yaml").write_text("id: broken\nimages: [unclosed\n", encoding="utf-8")
        (tmp_path / "valid.yaml").write_text(self.VALID_ENTRY, encoding="utf-8")
        kb = KnowledgeBase.load(tmp_path)
        assert [app.id for app in kb.apps] == ["valid"]
        assert kb.apps[0].exposure_recommendation == "lan"

    def test_entry_missing_the_id_key_is_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "no-id.yaml").write_text("name: No Id\nimages:\n  - noid/app\n",
                                             encoding="utf-8")
        (tmp_path / "valid.yaml").write_text(self.VALID_ENTRY, encoding="utf-8")
        kb = KnowledgeBase.load(tmp_path)
        assert [app.id for app in kb.apps] == ["valid"]

    def test_entry_missing_the_images_key_is_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "no-images.yaml").write_text("id: no-images\nname: No Images\n",
                                                 encoding="utf-8")
        (tmp_path / "valid.yaml").write_text(self.VALID_ENTRY, encoding="utf-8")
        kb = KnowledgeBase.load(tmp_path)
        assert [app.id for app in kb.apps] == ["valid"]

    def test_missing_directory_yields_an_empty_kb(self, tmp_path: Path) -> None:
        kb = KnowledgeBase.load(tmp_path / "does-not-exist")
        assert len(kb) == 0

    def test_wrong_typed_fields_are_skipped_without_raising(self, tmp_path: Path) -> None:
        # Syntactically valid YAML, but default_ports cannot be coerced to int
        # and images is a scalar: both must degrade to a skipped entry.
        (tmp_path / "bad-ports.yaml").write_text(
            "id: bad-ports\nimages:\n  - bad/app\ndefault_ports: [web]\n",
            encoding="utf-8",
        )
        (tmp_path / "scalar-images.yaml").write_text(
            "id: scalar-images\nimages: 42\n", encoding="utf-8"
        )
        (tmp_path / "valid.yaml").write_text(self.VALID_ENTRY, encoding="utf-8")
        kb = KnowledgeBase.load(tmp_path)
        assert [app.id for app in kb.apps] == ["valid"]


class TestBundledEntriesAreValid:
    """Schema-validate every YAML file shipped in kb/data/apps.

    The knowledge base is the project's primary contribution vector; this
    test is what keeps a typo'd exposure value or a silently-skipped entry
    from shipping.
    """

    DATA_DIR = Path(__import__("portcullis.kb", fromlist=["kb"]).__file__).parent / "data" / "apps"
    VALID_EXPOSURES = {"never", "proxy-only", "lan", "public-ok"}
    VALID_SENSITIVITIES = {"critical", "high", "medium", "low"}

    def test_every_yaml_file_loads_as_an_app(self) -> None:
        files = sorted(self.DATA_DIR.glob("*.yaml"))
        kb = KnowledgeBase.load(self.DATA_DIR)
        assert len(kb.apps) == len(files), "an entry was silently skipped at load time"

    def test_ids_are_unique_and_match_the_filename(self) -> None:
        kb = KnowledgeBase.load(self.DATA_DIR)
        ids = [app.id for app in kb.apps]
        assert len(ids) == len(set(ids))
        filenames = {file.stem for file in self.DATA_DIR.glob("*.yaml")}
        assert set(ids) == filenames

    #: Bare image patterns that are matched against an image's last path
    #: component (see AppInfo.matches). These are generic enough to collide
    #: with unrelated images (e.g. `server` matches `vaultwarden/server`), so a
    #: KB entry must qualify them with a repository path or a `*/name` wildcard.
    GENERIC_BARE_TOKENS = {
        "server", "core", "app", "web", "api", "db", "data", "backend",
        "frontend", "service", "main", "worker", "docker", "latest",
    }

    def test_every_entry_respects_the_schema(self) -> None:
        for app in KnowledgeBase.load(self.DATA_DIR).apps:
            assert app.exposure_recommendation in self.VALID_EXPOSURES, app.id
            assert app.sensitivity in self.VALID_SENSITIVITIES, app.id
            assert app.image_patterns, app.id
            assert all(isinstance(port, int) for port in app.default_ports), app.id
            for pattern in app.image_patterns:
                # No pattern that matches anything (bare "*" or "*x*").
                assert pattern.strip("*"), f"{app.id}: pattern {pattern!r} matches anything"
                assert not (pattern.startswith("*") and pattern.endswith("*")), (
                    f"{app.id}: pattern {pattern!r} is too broad"
                )
                # No generic bare token: it would overmatch unrelated images by
                # their last path component.
                assert pattern.lower() not in self.GENERIC_BARE_TOKENS, (
                    f"{app.id}: bare pattern {pattern!r} overmatches unrelated images; "
                    "qualify it with a repository path or a '*/name' wildcard"
                )


class TestExposedBeyondRecommendation:
    @pytest.mark.parametrize(
        ("recommendation", "exposure", "expected"),
        [
            # "never": nothing beyond the host itself.
            ("never", Exposure.INTERNAL, False),
            ("never", Exposure.HOST, False),
            ("never", Exposure.LAN, True),
            ("never", Exposure.INTERNET, True),
            # "proxy-only": only a directly published port (LAN) violates it;
            # INTERNET means "reached through the proxy", which is the point.
            ("proxy-only", Exposure.INTERNAL, False),
            ("proxy-only", Exposure.HOST, False),
            ("proxy-only", Exposure.LAN, True),
            ("proxy-only", Exposure.INTERNET, False),
            # "lan": fine on the local network, not on the Internet.
            ("lan", Exposure.HOST, False),
            ("lan", Exposure.LAN, False),
            ("lan", Exposure.INTERNET, True),
            # "public-ok": never violated.
            ("public-ok", Exposure.INTERNAL, False),
            ("public-ok", Exposure.HOST, False),
            ("public-ok", Exposure.LAN, False),
            ("public-ok", Exposure.INTERNET, False),
        ],
    )
    def test_recommendation_ceilings(
        self, recommendation: str, exposure: Exposure, expected: bool
    ) -> None:
        app = make_app(recommendation=recommendation)
        assert app.exposed_beyond_recommendation(exposure) is expected
