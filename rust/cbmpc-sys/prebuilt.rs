// Native artifacts this crate version links by default (build.rs, mode 3). Filled by a PR after a
// release tag's native-release.yml run, from that release's SHA256SUMS; empty means build from
// source. Only a maintainer-approved release tag goes here.

/// Release tag of nguyenkha/cb-mpc whose `cbmpc-native-<platform>.tar.gz` assets are linked.
const PREBUILT_TAG: &str = "";

/// (platform, sha256 of cbmpc-native-<platform>.tar.gz)
const PREBUILT: &[(&str, &str)] = &[];

const PREBUILT_BASE_URL: &str = "https://github.com/nguyenkha/cb-mpc/releases/download";
