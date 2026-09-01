package dev.gaphunter.ssrfunsanitizedurlcompanion.model

import com.intellij.psi.PsiElement

enum class HttpSinkKind {
    /** `java.net.http.HttpClient` -- `HttpRequest.newBuilder(URI.create(url))`. */
    JAVA_HTTP_CLIENT,

    /** Spring `RestTemplate` -- `getForObject`/`getForEntity`/`postForObject`/`exchange`/etc. */
    REST_TEMPLATE,

    /** OkHttp -- `new Request.Builder().url(url)...`. */
    OKHTTP,
}

/** One HTTP call whose URL/host argument traces back to an untrusted controller parameter, with no allowlist validation found in the same method. */
data class SsrfSinkHit(
    val anchor: PsiElement,
    val kind: HttpSinkKind,
    val taintedSourceName: String,
)
