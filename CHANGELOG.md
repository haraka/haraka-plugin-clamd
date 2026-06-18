# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/).

### Unreleased

### [1.0.5] - 2026-06-18

- fix(classify_outcome): guard against null transaction when client disconnects during scan

### [1.0.4] - 2026-06-17

- fix(scan_against): replace inactivity timeout with absolute timeout #6
- fix(scan_against): defer (vs hang) when a clamd_socket host is unparseable
- refactor(clamd_connect): parse via net_utils.endpoint
- refactor(hook_data_post): extract per-host outcome into classify_outcome
- refactor(hook_data_post): unbiased utils.shuffle for randomize_host_order
- test: refactored against test-fixtures 1.7.0 #5
- deps: bump versions

### [1.0.3] - 2026-05-24

- fix: declare `check.relay` in the booleans list
- fix(excludes): `!/regex/` exclude entries now strip the trailing `/`
- refactor(hook_data_post): into smaller functions
- refactor(load_excludes): collapsed into a loop plus a helper
- refactor(should_check): strict equality and a reasons table
- refactor: forEach -> for..of
- refactor: remove unneeded done callbacks
- ci: update triggers #3
- dep(@haraka/eslint): upgrade to v3

### [1.0.2] - 2025-01-30

- dep(eslint): upgrade to v9
- dep(all): bump to latest
- doc(CONTRIBUTORS): added

### [1.0.1] - 2024-05-08

- chore: formatting

### [1.0.0] - 2024-05-08

- initial release (repackaged from haraka/Haraka)

[1.0.0]: https://github.com/haraka/haraka-plugin-clamd/releases/tag/v1.0.0
[1.0.1]: https://github.com/haraka/haraka-plugin-clamd/releases/tag/v1.0.1
[1.0.2]: https://github.com/haraka/haraka-plugin-clamd/releases/tag/v1.0.2
[1.0.3]: https://github.com/haraka/haraka-plugin-clamd/releases/tag/v1.0.3
[1.0.4]: https://github.com/haraka/haraka-plugin-clamd/releases/tag/v1.0.4
[1.0.5]: https://github.com/haraka/haraka-plugin-clamd/releases/tag/v1.0.5
