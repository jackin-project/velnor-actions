//! Release-table validation, signer rendering, and live mirror checks.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use serde::Deserialize;

use crate::model::{ForkTable, is_sha40};
use crate::package::PackagePolicy;

const RELEASE_SCHEMA: &str = "velnor-actions.releases.v1";

/// The release table and its immutable fork/signer rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleasePolicy {
    releases: Vec<Release>,
}

/// One CalVer release and the mirror commits that comprise it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub calver: String,
    pub forks: Vec<ReleaseFork>,
    pub signers: Vec<SignerRelease>,
}

/// One owner-local fork commit for a release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseFork {
    pub owner: String,
    pub repository: String,
    pub sha: String,
}

/// One package consumer's signer rotation for a release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerRelease {
    pub consumer: String,
    pub source: String,
    pub signer_fork: String,
    pub current_signer_digest: String,
    pub old_signer_digest: Option<String>,
    pub old_signer_activated_at: Option<String>,
    pub old_signer_expires_at: Option<String>,
}

impl ReleasePolicy {
    /// Load and validate the release table syntax and immutable identities.
    pub fn load(root: &Path) -> Result<Self, String> {
        let path = root.join("fleet/releases.toml");
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("reading {}: {e}", path.display()))?;
        let file: ReleasesFile =
            toml::from_str(&text).map_err(|e| format!("parsing {}: {e}", path.display()))?;
        if file.schema != RELEASE_SCHEMA {
            return Err(format!("unknown release table schema {:?}", file.schema));
        }
        if file.release.is_empty() {
            return Err("release table must declare at least one release".into());
        }
        let mut seen = BTreeSet::new();
        let mut releases = Vec::with_capacity(file.release.len());
        for row in file.release {
            validate_calver(&row.calver)?;
            if !seen.insert(row.calver.clone()) {
                return Err(format!("duplicate release {:?}", row.calver));
            }
            let mut fork_seen = BTreeSet::new();
            let forks = row
                .fork
                .into_iter()
                .map(|fork| {
                    if !fork_seen.insert(fork.repository.clone())
                        || fork.repository != format!("{}/velnor-actions", fork.owner)
                        || !is_sha40(&fork.sha)
                    {
                        return Err(format!(
                            "invalid or duplicate release fork {}@{}",
                            fork.repository, fork.sha
                        ));
                    }
                    Ok(ReleaseFork {
                        owner: fork.owner,
                        repository: fork.repository,
                        sha: fork.sha,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            let mut signer_seen = BTreeSet::new();
            let signers = row
                .signer
                .into_iter()
                .map(|signer| {
                    if !signer_seen.insert(signer.consumer.clone())
                        || !is_sha40(&signer.current_signer_digest)
                    {
                        return Err(format!(
                            "invalid or duplicate signer row {:?}",
                            signer.consumer
                        ));
                    }
                    let old = [
                        signer.old_signer_digest.as_ref(),
                        signer.old_signer_activated_at.as_ref(),
                        signer.old_signer_expires_at.as_ref(),
                    ];
                    if old.iter().any(Option::is_some) && old.iter().any(Option::is_none) {
                        return Err(format!(
                            "signer rotation for {} must declare all old fields",
                            signer.consumer
                        ));
                    }
                    if let Some(digest) = signer.old_signer_digest.as_deref() {
                        if !is_sha40(digest) || digest == signer.current_signer_digest {
                            return Err(format!(
                                "signer rotation for {} has an invalid old digest",
                                signer.consumer
                            ));
                        }
                        let activated = signer
                            .old_signer_activated_at
                            .as_deref()
                            .unwrap_or_default();
                        let expires = signer.old_signer_expires_at.as_deref().unwrap_or_default();
                        if !looks_rfc3339_utc(activated)
                            || !looks_rfc3339_utc(expires)
                            || activated >= expires
                        {
                            return Err(format!(
                                "signer rotation for {} has invalid UTC bounds",
                                signer.consumer
                            ));
                        }
                        let activated_seconds = utc_seconds(activated).ok_or_else(|| {
                            format!(
                                "signer rotation for {} has invalid activation",
                                signer.consumer
                            )
                        })?;
                        let expires_seconds = utc_seconds(expires).ok_or_else(|| {
                            format!("signer rotation for {} has invalid expiry", signer.consumer)
                        })?;
                        if expires_seconds > activated_seconds + 30 * 24 * 60 * 60 {
                            return Err(format!(
                                "signer rotation for {} exceeds the 30-day old-signer window",
                                signer.consumer
                            ));
                        }
                    }
                    Ok(SignerRelease {
                        consumer: signer.consumer,
                        source: signer.source,
                        signer_fork: signer.signer_fork,
                        current_signer_digest: signer.current_signer_digest,
                        old_signer_digest: signer.old_signer_digest,
                        old_signer_activated_at: signer.old_signer_activated_at,
                        old_signer_expires_at: signer.old_signer_expires_at,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            releases.push(Release {
                calver: row.calver,
                forks,
                signers,
            });
        }
        Ok(Self { releases })
    }

    /// Validate release rows against the fork and package tables.
    pub fn validate_against(
        &self,
        packages: &PackagePolicy,
        forks: &ForkTable,
    ) -> Result<(), String> {
        let fork_repositories: BTreeSet<_> = forks
            .entries()
            .iter()
            .map(|fork| fork.repository.as_str())
            .collect();
        let package_consumers: BTreeSet<_> = packages.consumer_slugs().collect();
        for release in &self.releases {
            if release.forks.len() != forks.entries().len() {
                return Err(format!(
                    "release {} has {} forks, expected {}",
                    release.calver,
                    release.forks.len(),
                    forks.entries().len()
                ));
            }
            let mut release_repositories = BTreeSet::new();
            for fork in &release.forks {
                if !fork_repositories.contains(fork.repository.as_str())
                    || !release_repositories.insert(fork.repository.as_str())
                {
                    return Err(format!(
                        "release {} fork {} is not exactly one declared fork",
                        release.calver, fork.repository
                    ));
                }
            }
            if release_repositories != fork_repositories {
                return Err(format!(
                    "release {} fork set differs from fork table",
                    release.calver
                ));
            }
            let mut signer_consumers = BTreeSet::new();
            for signer in &release.signers {
                let package = packages.consumer(signer.consumer.as_str()).ok_or_else(|| {
                    format!(
                        "release {} has unknown signer consumer {}",
                        release.calver, signer.consumer
                    )
                })?;
                if !signer_consumers.insert(signer.consumer.as_str())
                    || signer.source != package.source()
                {
                    return Err(format!(
                        "release {} signer row {} does not match package source",
                        release.calver, signer.consumer
                    ));
                }
                if !fork_repositories.contains(signer.signer_fork.as_str()) {
                    return Err(format!(
                        "release {} signer {} is not a declared fork",
                        release.calver, signer.signer_fork
                    ));
                }
                let expected_owner = signer.source().split('/').next().unwrap_or_default();
                let actual_owner = signer.signer_fork.split('/').next().unwrap_or_default();
                if expected_owner != actual_owner {
                    return Err(format!(
                        "release {} signer {} crosses source owner boundary",
                        release.calver, signer.consumer
                    ));
                }
            }
            if signer_consumers != package_consumers {
                return Err(format!(
                    "release {} signer consumer set differs from package table",
                    release.calver
                ));
            }
        }
        Ok(())
    }

    /// Return one validated release by CalVer.
    pub fn release(&self, calver: &str) -> Result<&Release, String> {
        self.releases
            .iter()
            .find(|release| release.calver == calver)
            .ok_or_else(|| format!("release table has no CalVer {calver}"))
    }

    /// Render the fixed-name signer table consumed by package updater workflows.
    pub fn render_signer_digests(
        &self,
        packages: &PackagePolicy,
        consumer: &str,
        calver: &str,
    ) -> Result<String, String> {
        let release = self.release(calver)?;
        let signer = release
            .signers
            .iter()
            .find(|signer| signer.consumer == consumer)
            .ok_or_else(|| format!("release {calver} has no signer row for {consumer}"))?;
        let package = packages
            .consumer(consumer)
            .ok_or_else(|| format!("{consumer:?} is not a package consumer"))?;
        if signer.source != package.source() {
            return Err(format!("signer source mismatch for {consumer}"));
        }
        let mut out = format!(
            "# Generated by velnor-actions-generator. DO NOT EDIT.\nschema = \"velnor-actions.signer-digests.v1\"\nrelease = \"{}\"\nconsumer = \"{}\"\nsource = \"{}\"\nsigner_fork = \"{}\"\ncurrent_signer_digest = \"{}\"\n",
            release.calver,
            signer.consumer,
            signer.source,
            signer.signer_fork,
            signer.current_signer_digest
        );
        if let (Some(digest), Some(activated), Some(expires)) = (
            signer.old_signer_digest.as_deref(),
            signer.old_signer_activated_at.as_deref(),
            signer.old_signer_expires_at.as_deref(),
        ) {
            out.push_str(&format!("old_signer_digest = \"{digest}\"\n"));
            out.push_str(&format!("old_signer_activated_at = \"{activated}\"\n"));
            out.push_str(&format!("old_signer_expires_at = \"{expires}\"\n"));
        }
        Ok(out)
    }

    /// Resolve every release tag and prove all declared mirrors have identical
    /// blob paths, modes, and object IDs. This is deliberately an explicit live
    /// release check; ordinary local generation stays offline and deterministic.
    pub fn check_fork_equality(&self, forks: &ForkTable, calver: &str) -> Result<String, String> {
        let release = self.release(calver)?;
        let expected_repositories: BTreeSet<_> = forks
            .entries()
            .iter()
            .map(|f| f.repository.as_str())
            .collect();
        let mut trees: Vec<(String, BTreeMap<String, String>)> = Vec::new();
        for fork in &release.forks {
            if !expected_repositories.contains(fork.repository.as_str()) {
                return Err(format!(
                    "release {calver} contains undeclared fork {}",
                    fork.repository
                ));
            }
            let commit = resolve_release_ref(&fork.repository, calver)?;
            if commit != fork.sha {
                return Err(format!(
                    "release {calver} table SHA mismatch for {}: table {}, tag {}",
                    fork.repository, fork.sha, commit
                ));
            }
            trees.push((
                fork.repository.clone(),
                fetch_tree(&fork.repository, &commit)?,
            ));
        }
        let Some((first_repository, first_tree)) = trees.first() else {
            return Err(format!("release {calver} has no fork trees"));
        };
        for (repository, tree) in trees.iter().skip(1) {
            if tree != first_tree {
                let first_paths: BTreeSet<_> = first_tree.keys().collect();
                let paths: BTreeSet<_> = tree.keys().collect();
                return Err(format!(
                    "release {calver} fork mismatch: {first_repository} vs {repository}; missing={:?}, extra={:?}",
                    first_paths.difference(&paths).collect::<Vec<_>>(),
                    paths.difference(&first_paths).collect::<Vec<_>>()
                ));
            }
        }
        Ok(format!(
            "release fork equality valid: {calver}, {} forks, {} blobs",
            trees.len(),
            first_tree.len()
        ))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleasesFile {
    schema: String,
    #[serde(default)]
    release: Vec<ReleaseFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseFile {
    calver: String,
    #[serde(default)]
    fork: Vec<ReleaseForkFile>,
    #[serde(default)]
    signer: Vec<SignerFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseForkFile {
    owner: String,
    repository: String,
    sha: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignerFile {
    consumer: String,
    source: String,
    signer_fork: String,
    current_signer_digest: String,
    #[serde(default)]
    old_signer_digest: Option<String>,
    #[serde(default)]
    old_signer_activated_at: Option<String>,
    #[serde(default)]
    old_signer_expires_at: Option<String>,
}

fn validate_calver(value: &str) -> Result<(), String> {
    let parts: Vec<_> = value.split('.').collect();
    if parts.len() != 3
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(format!("invalid release CalVer {value:?}"));
    }
    Ok(())
}

fn looks_rfc3339_utc(value: &str) -> bool {
    value.len() == 20
        && value.ends_with('Z')
        && value.as_bytes()[4] == b'-'
        && value.as_bytes()[7] == b'-'
        && value.as_bytes()[10] == b'T'
        && value.as_bytes()[13] == b':'
        && value.as_bytes()[16] == b':'
        && value[..19].bytes().filter(|b| b.is_ascii_digit()).count() == 14
}

fn utc_seconds(value: &str) -> Option<i64> {
    if !looks_rfc3339_utc(value) {
        return None;
    }
    let number = |start: usize, end: usize| value[start..end].parse::<i64>().ok();
    let year = number(0, 4)?;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let hour = number(11, 13)?;
    let minute = number(14, 16)?;
    let second = number(17, 19)?;
    if year < 1970 || !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    let mut days = 0_i64;
    for current_year in 1970..year {
        days += if is_leap_year(current_year) { 366 } else { 365 };
    }
    for current_month in 1..month {
        days += days_in_month(year, current_month);
    }
    Some((days + day - 1) * 86_400 + hour * 3_600 + minute * 60 + second)
}

fn is_leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if is_leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn resolve_release_ref(repository: &str, calver: &str) -> Result<String, String> {
    let endpoint = format!("repos/{repository}/git/ref/tags/{calver}");
    let row = gh_api(&endpoint, "[.object.type,.object.sha]|@tsv")?;
    let mut parts = row.trim().split('\t');
    let mut kind = parts.next().unwrap_or_default().to_string();
    let mut sha = parts.next().unwrap_or_default().to_string();
    if kind.is_empty() || sha.is_empty() {
        return Err(format!("release {calver} tag missing for {repository}"));
    }
    while kind == "tag" {
        let row = gh_api(
            &format!("repos/{repository}/git/tags/{sha}"),
            "[.object.type,.object.sha]|@tsv",
        )?;
        let mut parts = row.trim().split('\t');
        kind = parts.next().unwrap_or_default().to_string();
        sha = parts.next().unwrap_or_default().to_string();
    }
    if kind != "commit" || !is_sha40(&sha) {
        return Err(format!(
            "release {calver} tag for {repository} does not resolve to a commit"
        ));
    }
    Ok(sha)
}

fn fetch_tree(repository: &str, commit: &str) -> Result<BTreeMap<String, String>, String> {
    let endpoint = format!("repos/{repository}/git/trees/{commit}?recursive=1");
    let output = gh_api(
        &endpoint,
        "[.tree[] | select(.type == \"blob\") | [.path,.mode,.sha] | @tsv] | sort | .[]",
    )?;
    let mut tree = BTreeMap::new();
    for row in output.lines().filter(|line| !line.is_empty()) {
        let mut fields = row.splitn(3, '\t');
        let path = fields.next().unwrap_or_default();
        let mode = fields.next().unwrap_or_default();
        let sha = fields.next().unwrap_or_default();
        if path.is_empty() || mode.is_empty() || !is_sha40(sha) {
            return Err(format!(
                "invalid tree entry for {repository}@{commit}: {row:?}"
            ));
        }
        tree.insert(path.to_string(), format!("{mode}\t{sha}"));
    }
    Ok(tree)
}

fn gh_api(endpoint: &str, jq: &str) -> Result<String, String> {
    let output = Command::new("gh")
        .args(["api", endpoint, "--jq", jq])
        .output()
        .map_err(|error| format!("release check could not execute gh: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "gh api {endpoint} failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

impl SignerRelease {
    fn source(&self) -> &str {
        &self.source
    }
}
