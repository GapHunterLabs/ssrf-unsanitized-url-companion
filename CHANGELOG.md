<!-- Keep a Changelog guide -> https://keepachangelog.com -->

# SSRF via Unsanitized URL Companion Changelog

## [Unreleased]

## [0.1.0]

### Added

- Warning on an HTTP call (`HttpRequest.newBuilder`, `RestTemplate`,
  OkHttp's `Request.Builder`) whose URL/host argument traces back to
  an untrusted controller parameter (same method, one direct hop), with
  no allowlist check found in the same method -- CWE-918, Server-Side
  Request Forgery.

[Unreleased]: https://github.com/GapHunterLabs/ssrf-unsanitized-url-companion/compare/0.1.0...HEAD
[0.1.0]: https://github.com/GapHunterLabs/ssrf-unsanitized-url-companion/commits/0.1.0
