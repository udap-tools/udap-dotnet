#!/usr/bin/env bash
# Packs every published Udap.* package at one version into an output folder:
#   <output>/<package>.<version>.nupkg   with its CycloneDX SBOM inside, at sbom/<package>.cdx.json
#   <output>/<package>.<version>.snupkg  symbols for the nuget.org symbol server
#   <output>/sbom/<package>.cdx.json     the same SBOMs, for the GitHub release
# Packing also runs package validation against the baseline release (see Common.props).
#
# usage: pack.sh <version> [output]   (run from the repository root after dotnet restore and dotnet tool restore)
set -euo pipefail

version=$1
output=${2:-artifacts}

# Keep in step with UdapPackages in Common.props.
packages=(
  Udap.Model Udap.Util Udap.Common Udap.Metadata.Server Udap.Server Udap.Server.Storage
  Udap.Client Udap.UI Udap.Smart.Model Udap.Smart.Metadata Udap.CdsHooks.Endpoint
  Udap.CdsHooks.Model Udap.Tefca.Model Udap.Tefca.Server Udap.Ssraa.Server
)

mkdir -p "$output/sbom"
sbom=$(cd "$output/sbom" && pwd)

for package in "${packages[@]}"; do
  # The dependencies this package brings to consumers, including the other Udap.* packages it references.
  # SourceLink is build-only and never reaches consumers.
  dotnet dotnet-CycloneDX "$package/$package.csproj" -o "$sbom" -F Json -fn "$package.cdx.json" \
    --set-type Library --include-project-references --set-nuget-purl \
    --set-name "$package" --set-version "$version" \
    --exclude-filter Microsoft.SourceLink.GitHub

  dotnet pack "$package/$package.csproj" -c Release -o "$output" \
    -p:PackageVersion="$version" -p:UdapSbomDirectory="$sbom"
done
