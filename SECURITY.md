# Security Policy

## Supported versions

The Udap.* packages on nuget.org are the product. Security fixes go into the next release of the latest
version line; older versions are not patched, so upgrade to the latest release to pick up a fix.

| Version          | Supported |
|------------------|-----------|
| Latest 0.9.x     | Yes       |
| Earlier versions | No        |

The projects under `examples/` are reference implementations used for testing and demonstration. They are not
hardened for production use, but reports about them are welcome.

## Reporting a vulnerability

Please do not open a public issue, discussion or pull request for a vulnerability.

Report it privately through GitHub: on the repository's **Security** tab choose **Report a vulnerability**
(https://github.com/JoeShook/udap-dotnet/security/advisories/new). Include the affected package and version,
what an attacker can do, and the steps or code to reproduce it.

You can expect an acknowledgement within 10 business days. Once the issue is confirmed, the fix ships in the
next release to nuget.org, and the release notes credit you unless you prefer otherwise.

## Verifying the packages

Each release is built and published by the `release.yml` workflow from a version tag in this repository.

- **SBOM:** every `.nupkg` contains a CycloneDX SBOM of the dependencies it brings, at `sbom/<package>.cdx.json`.
  The same files are attached to the GitHub release.
- **Provenance:** the packages and SBOMs attached to each GitHub release carry a build provenance attestation.
  Verify a downloaded file with:

  ```bash
  gh attestation verify Udap.Common.1.0.0.nupkg --repo JoeShook/udap-dotnet
  ```

  nuget.org adds its own repository signature to every package it accepts, which changes the file, so verify the
  copies from the GitHub release rather than the ones restored from nuget.org.
- **Source:** the packages are built with SourceLink and deterministic build settings, and each `.nuspec`
  records the repository commit it was built from.
- **Dependencies:** a release is refused if any dependency, direct or transitive, on any target framework has a
  known vulnerability.
