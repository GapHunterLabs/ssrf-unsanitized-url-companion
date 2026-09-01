# Demo data for screenshots

`FetchController.java` — `fetchWithHttpClient`/`fetchWithRestTemplate`
flagged; `fetchSafe` not flagged (allowlist check present).

## How to get the screenshot

1. `./gradlew runIde` from `ssrf-unsanitized-url-companion`, open this
   `demo/` folder as the project.
2. Full Screen, open `FetchController.java` — warnings should appear on
   the first two methods' HTTP calls but not on `fetchSafe`.
3. Screenshot with all three methods visible, save into
   `ssrf-unsanitized-url-companion/docs/screenshots/`. Close the
   sandbox.
