package dev.gaphunter.ssrfunsanitizedurlcompanion.detect

/**
 * Broad text signals this plugin accepts as evidence that a method
 * already validates a URL/host against an allowlist before using it --
 * a cosmetic check (e.g. a null check) does not reduce SSRF risk, so
 * only names that plausibly indicate real allowlist logic count.
 * Deliberately broad substring matches (not resolved calls), same
 * "match a known name, don't resolve a symbol" discipline as
 * `SignatureVerificationSignals` in `webhook-signature-companion`.
 */
object ValidationSignals {

    private val ALLOWLIST_FRAGMENTS = listOf("allowlist", "whitelist", "isallowedhost", "isvalidhost", "isallowedurl")

    fun bodyLooksValidated(bodyText: String): Boolean {
        val lower = bodyText.lowercase()
        return ALLOWLIST_FRAGMENTS.any { lower.contains(it) }
    }
}
