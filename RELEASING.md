# Releasing Portcullis

Releases are built and published to [PyPI](https://pypi.org/project/portcullis/)
automatically by [`.github/workflows/release.yml`](.github/workflows/release.yml)
when a `v*` tag is pushed. Publishing uses **PyPI trusted publishing** (OIDC),
so there is no token to manage in the repository.

## One-time setup (PyPI side)

Do this once, before the first release:

1. Create the PyPI project (either publish `0.1.0` manually once, or configure a
   *pending* trusted publisher on a not-yet-existing project).
2. On PyPI → the `portcullis` project → *Publishing* → add a **GitHub Actions**
   trusted publisher:
   - Owner: `yakohhhh`
   - Repository: `portcullis`
   - Workflow: `release.yml`
   - Environment: `pypi`
3. In the GitHub repo, create an environment named `pypi` (Settings →
   Environments). Optionally require a reviewer to approve each publish.

> If the name `portcullis` is ever taken before the first publish, fall back to
> `portcullis-audit` in `pyproject.toml` (the CLI command stays `portcullis`).

## Cutting a release

1. Choose the version. While in `0.x`, a minor bump may carry breaking changes;
   otherwise follow [SemVer](https://semver.org).
2. Update `version` in `pyproject.toml`.
3. Move the `## [Unreleased]` entries into a new `## [X.Y.Z] - YYYY-MM-DD`
   section in `CHANGELOG.md`, and refresh the compare/link footnotes.
4. Commit, open a PR, merge to `main`.
5. Tag and push:

   ```sh
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

The release workflow then:

- verifies the tag matches `pyproject.toml`'s version;
- builds the sdist and wheel and runs `twine check`;
- runs an install smoke test (`portcullis --version` from the built wheel);
- publishes to PyPI via trusted publishing;
- creates a GitHub Release with the notes taken from `CHANGELOG.md`.

## Marketplace listing (GitHub Action)

Once a release exists, publish the action to the GitHub Marketplace from the
release page ("Publish this Action to the Marketplace"), so consumers can pin
`uses: yakohhhh/portcullis@v1`. Keep a moving major tag (`v1`) pointing at the
latest compatible release.
