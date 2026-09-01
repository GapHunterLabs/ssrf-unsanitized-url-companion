package dev.gaphunter.ssrfunsanitizedurlcompanion.detect

import com.intellij.psi.JavaRecursiveElementWalkingVisitor
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiExpression
import com.intellij.psi.PsiFile
import com.intellij.psi.PsiMethod
import com.intellij.psi.PsiMethodCallExpression
import com.intellij.psi.PsiNewExpression
import com.intellij.psi.PsiReferenceExpression
import dev.gaphunter.ssrfunsanitizedurlcompanion.model.HttpSinkKind
import dev.gaphunter.ssrfunsanitizedurlcompanion.model.SsrfSinkHit

/**
 * Follows the real data flow (bounded to the SAME method, one direct
 * hop to a parameter -- never a full project-wide taint analysis)
 * from an untrusted source (a parameter of a Spring MVC/JAX-RS
 * endpoint method, see [ControllerEndpointSignals]) to an HTTP call
 * whose URL/host argument is built directly from it, without a
 * whitelist check in the same method -- CWE-918, Server-Side Request
 * Forgery.
 *
 * **v0.1 scope, stated honestly:** a closed list of known HTTP sinks
 * (`java.net.http.HttpClient`'s `HttpRequest.newBuilder(...)`, Spring's
 * `RestTemplate`, OkHttp's `Request.Builder`), one method of distance,
 * no general taint analysis of the whole project. Flags at the point
 * the tainted URL enters the request construction (`HttpRequest.newBuilder(...)`/
 * `RestTemplate.getForObject(...)`/`Request.Builder().url(...)`), not at
 * a later `.send()`/`.execute()` call.
 */
object JavaSsrfSinkFinder {

    private val REST_TEMPLATE_METHODS = setOf(
        "getForObject", "getForEntity", "postForObject", "postForEntity",
        "put", "exchange", "delete", "execute", "patchForObject",
    )

    fun findAll(file: PsiFile): List<SsrfSinkHit> {
        val hits = mutableListOf<SsrfSinkHit>()
        file.accept(object : JavaRecursiveElementWalkingVisitor() {
            override fun visitMethod(method: PsiMethod) {
                super.visitMethod(method)
                if (!ControllerEndpointSignals.isEndpointMethod(method)) return
                hits += hitsForMethod(method)
            }
        })
        return hits
    }

    private fun hitsForMethod(method: PsiMethod): List<SsrfSinkHit> {
        val body = method.body ?: return emptyList()
        val taintedNames = method.parameterList.parameters.map { it.name }.toSet()
        if (taintedNames.isEmpty()) return emptyList()
        if (ValidationSignals.bodyLooksValidated(body.text)) return emptyList()

        val hits = mutableListOf<SsrfSinkHit>()
        body.accept(object : JavaRecursiveElementWalkingVisitor() {
            override fun visitMethodCallExpression(expression: PsiMethodCallExpression) {
                super.visitMethodCallExpression(expression)
                hitForHttpClient(expression, taintedNames)?.let { hits += it }
                hitForRestTemplate(expression, taintedNames)?.let { hits += it }
                hitForOkHttp(expression, taintedNames)?.let { hits += it }
            }
        })
        return hits
    }

    /** `HttpRequest.newBuilder(argExpr)` where `argExpr` (e.g. `URI.create(param)`) references a tainted parameter. */
    private fun hitForHttpClient(call: PsiMethodCallExpression, taintedNames: Set<String>): SsrfSinkHit? {
        val methodExpr = call.methodExpression
        if (methodExpr.referenceName != "newBuilder") return null
        val qualifier = methodExpr.qualifierExpression ?: return null
        if (qualifier.text != "HttpRequest" && qualifier.text != "java.net.http.HttpRequest") return null
        val arg = call.argumentList.expressions.getOrNull(0) ?: return null
        val taintedName = firstTaintedReference(arg, taintedNames) ?: return null
        return SsrfSinkHit(anchorOf(methodExpr), HttpSinkKind.JAVA_HTTP_CLIENT, taintedName)
    }

    /** `restTemplate.getForObject(argExpr, ...)` (or any other known RestTemplate method) where `argExpr` references a tainted parameter. */
    private fun hitForRestTemplate(call: PsiMethodCallExpression, taintedNames: Set<String>): SsrfSinkHit? {
        val methodExpr = call.methodExpression
        if (methodExpr.referenceName !in REST_TEMPLATE_METHODS) return null
        val qualifier = methodExpr.qualifierExpression as? PsiExpression ?: return null
        val qualifierTypeText = qualifier.type?.canonicalText ?: return null
        if (!qualifierTypeText.contains("RestTemplate")) return null
        val arg = call.argumentList.expressions.getOrNull(0) ?: return null
        val taintedName = firstTaintedReference(arg, taintedNames) ?: return null
        return SsrfSinkHit(anchorOf(methodExpr), HttpSinkKind.REST_TEMPLATE, taintedName)
    }

    /** `new Request.Builder()....url(argExpr)...` where `argExpr` references a tainted parameter. */
    private fun hitForOkHttp(call: PsiMethodCallExpression, taintedNames: Set<String>): SsrfSinkHit? {
        val methodExpr = call.methodExpression
        if (methodExpr.referenceName != "url") return null
        val qualifier = methodExpr.qualifierExpression ?: return null
        if (!chainOriginatesFromRequestBuilder(qualifier)) return null
        val arg = call.argumentList.expressions.getOrNull(0) ?: return null
        val taintedName = firstTaintedReference(arg, taintedNames) ?: return null
        return SsrfSinkHit(anchorOf(methodExpr), HttpSinkKind.OKHTTP, taintedName)
    }

    /** Walks a `.foo().bar().baz()` call chain down to its root, true if that root is `new Request.Builder()`. */
    private fun chainOriginatesFromRequestBuilder(expression: PsiElement): Boolean {
        var current = expression
        while (current is PsiMethodCallExpression) {
            current = current.methodExpression.qualifierExpression ?: return false
        }
        val newExpression = current as? PsiNewExpression ?: return false
        return newExpression.classReference?.referenceName == "Builder"
    }

    /** The first tainted parameter name referenced anywhere inside [expression]'s own subtree (a direct reference, or one hop through a wrapping call like `URI.create(param)`). */
    private fun firstTaintedReference(expression: PsiElement, taintedNames: Set<String>): String? {
        var found: String? = null
        expression.accept(object : JavaRecursiveElementWalkingVisitor() {
            override fun visitReferenceExpression(expr: PsiReferenceExpression) {
                if (found != null) return
                super.visitReferenceExpression(expr)
                val name = expr.referenceName
                if (name != null && name in taintedNames) found = name
            }
        })
        return found
    }

    /**
     * Anchors on the method NAME identifier of a reference expression
     * (e.g. "newBuilder"/"getForObject"/"url"), never a blind
     * `firstChild` descent -- that can land on an empty
     * `PsiReferenceParameterList` node (present even with no explicit
     * generics), which the platform rejects with "Empty PSI elements
     * must not be passed to createDescriptor" (confirmed the hard way
     * in this catalog's ReDoS and JWT-timing-safe plugins).
     */
    private fun anchorOf(methodExpr: PsiReferenceExpression): PsiElement = methodExpr.referenceNameElement ?: methodExpr
}
