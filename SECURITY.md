# Security Policy

## Reporting a vulnerability

If you find a vulnerability in Portcullis itself, please report it privately through
[GitHub private security advisories](https://github.com/yakohhhh/portcullis/security/advisories/new)
on this repository. Do not open a public issue for security problems.

Please include a proof-of-concept input (e.g. the compose or YAML file that triggers the bug) and
the version or commit you tested. You should get a first response within a week; fixes for
confirmed issues are released as fast as the alpha pace allows, and reporters are credited in the
advisory unless they prefer otherwise.

## Supported versions

Portcullis is in alpha. Only the **latest release** (and the `main` branch) receives security
fixes. Please update before reporting.

## Scope: parser bugs are security bugs

Portcullis's core job is to **read untrusted configuration files** - docker-compose files from
arbitrary repositories, and community-contributed knowledge base YAML. That makes the parsing
surface the security boundary of the project:

- Anything a crafted input file can do beyond producing a report - code execution, file reads
  outside the scanned tree, resource exhaustion, crashes - is a security bug and in scope.
- YAML is only ever loaded with `yaml.safe_load`. A change introducing `yaml.load` (or any other
  construct that instantiates arbitrary objects from input files) is a vulnerability, not a style
  issue.
- A malformed knowledge base entry or compose file must degrade the scan, never break or hijack
  it.

Findings *about the user's infrastructure* (what Portcullis reports) are the product, not a
vulnerability in Portcullis - false positives and missed checks belong in regular issues.
