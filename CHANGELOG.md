<!-- Keep a Changelog guide -> https://keepachangelog.com -->

# SSRF via Unsanitized URL Companion Changelog

## [Unreleased]

### Added

- A description page for the inspection in **Settings | Editor |
  Inspections**, which showed "Under construction".

### Changed

- The rating prompt's local counter keeps one-way fingerprints of findings
  instead of their file paths, and deletes the list that earlier versions
  kept.
- `PRIVACY.md` describes the values the plugin keeps in the IDE's local
  settings.

## [0.1.1]

### Fixed

- Review/star CTA now links to this plugin's own Marketplace
  reviews page instead of the vendor's generic plugin list.

## [0.1.0]

### Added

- Warning on an HTTP call (`HttpRequest.newBuilder`, `RestTemplate`,
  OkHttp's `Request.Builder`) whose URL/host argument traces back to
  an untrusted controller parameter (same method, one direct hop), with
  no allowlist check found in the same method -- CWE-918, Server-Side
  Request Forgery.

[Unreleased]: https://github.com/GapHunterLabs/ssrf-unsanitized-url-companion/compare/0.1.1...HEAD
[0.1.1]: https://github.com/GapHunterLabs/ssrf-unsanitized-url-companion/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/GapHunterLabs/ssrf-unsanitized-url-companion/commits/0.1.0
