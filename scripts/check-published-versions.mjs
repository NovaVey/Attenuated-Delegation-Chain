#!/usr/bin/env node
// Fails loud if any publishable @adc/* workspace package's current
// package.json version is already live on the public npm registry.
//
// This is the exact mistake NovaVey's other repos have already been
// bitten by once (see taint-tracked-tool-broker's own CHANGELOG): a
// package's main branch drifted three feature PRs ahead of its last
// publish without `version` ever moving, so a git checkout of main and
// the real, already-published tarball for that same version string
// silently contained different code — a type-drift trap for anything
// consuming the package by git reference rather than by registry
// version (the concrete case that surfaced it there: a sibling repo
// building dist/ directly from a git submodule checkout of main — the
// exact way Control-Coverage-Range consumes this repo's own @adc/*
// packages today).
//
// The rule this enforces, adopted from those repos: once any @adc/*
// package is ever actually published, main must always sit on an
// unpublished version — ordinarily a `-dev.N` prerelease strictly above
// the last real release — never reused, never left pointing at a
// version that's already live. As of this script's own writing, none of
// these packages have been published yet (confirmed directly against
// the registry), so this should never fire in the ordinary course of
// development; it exists to catch the day that changes, loudly and
// immediately, rather than leaving it to be discovered later as a
// confusing downstream bug — see README.md's own "Versioning" section.
//
// Skips every workspace package marked "private": true (adc-testkit,
// mint-service) — those are never published, so there's nothing for
// their version to collide with.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

function discoverPublishableWorkspacePackages() {
  const packages = [];
  for (const group of ["packages", "services"]) {
    const groupDir = join(REPO_ROOT, group);
    if (!existsSync(groupDir)) continue;
    for (const entry of readdirSync(groupDir, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const pkgJsonPath = join(groupDir, entry.name, "package.json");
      if (!existsSync(pkgJsonPath)) continue;
      const pkgJson = JSON.parse(readFileSync(pkgJsonPath, "utf8"));
      if (pkgJson.private === true) continue;
      packages.push({ path: pkgJsonPath, name: pkgJson.name, version: pkgJson.version });
    }
  }
  return packages;
}

// `npm view <name>@<version> version` exits 0 with output only when that
// exact version is already published, and non-zero (E404) otherwise — no
// auth needed to query a public package's own metadata.
function isAlreadyPublished(name, version) {
  try {
    execFileSync("npm", ["view", `${name}@${version}`, "version"], { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

const packages = discoverPublishableWorkspacePackages();
if (packages.length === 0) {
  console.log("check-published-versions: no publishable workspace packages found — nothing to check.");
  process.exit(0);
}

let failed = false;
for (const pkg of packages) {
  if (isAlreadyPublished(pkg.name, pkg.version)) {
    console.error(
      `::error file=${pkg.path}::${pkg.name}@${pkg.version} is already published to npm — bump it before merging (main must always sit on an unpublished version, ordinarily a *-dev.N prerelease above the last real release).`,
    );
    failed = true;
  } else {
    console.log(`check-published-versions: ${pkg.name}@${pkg.version} is not published — OK.`);
  }
}

process.exit(failed ? 1 : 0);
