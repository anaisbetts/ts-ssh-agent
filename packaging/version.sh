#!/usr/bin/env bash
# Prints the package version for the current CI build: the release tag
# without its leading "v", or a pre-release version for any other build that
# sorts below 0.0.1 for both dpkg and pacman.
set -euo pipefail

if [[ "${GITHUB_REF:-}" == refs/tags/v* ]]; then
  echo "${GITHUB_REF#refs/tags/v}"
else
  echo "0.0.0.r${GITHUB_RUN_NUMBER:-0}.g$(git rev-parse --short=7 HEAD)"
fi
