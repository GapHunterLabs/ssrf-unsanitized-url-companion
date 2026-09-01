package dev.gaphunter.ssrfunsanitizedurlcompanion.inspection

import com.intellij.codeInspection.InspectionManager
import com.intellij.codeInspection.LocalInspectionTool
import com.intellij.codeInspection.ProblemDescriptor
import com.intellij.codeInspection.ProblemHighlightType
import com.intellij.psi.PsiFile
import com.intellij.psi.PsiJavaFile
import dev.gaphunter.ssrfunsanitizedurlcompanion.detect.JavaSsrfSinkFinder
import dev.gaphunter.ssrfunsanitizedurlcompanion.model.HttpSinkKind
import dev.gaphunter.ssrfunsanitizedurlcompanion.model.SsrfSinkHit
import dev.gaphunter.ssrfunsanitizedurlcompanion.review.ReviewPrompt

/**
 * Flags an HTTP call (`HttpRequest.newBuilder(...)`/`RestTemplate`/
 * OkHttp's `Request.Builder`) whose URL/host argument traces back
 * (within the same method, one direct hop) to an untrusted Spring
 * MVC/JAX-RS controller parameter, with no allowlist validation found
 * in the same method -- CWE-918, Server-Side Request Forgery.
 *
 * Runs via `checkFile` (same shape as every other inspection in this
 * catalog); [JavaSsrfSinkFinder] does the real PSI walk.
 */
class SsrfSinkInspection : LocalInspectionTool() {

    companion object {
        const val MAX_FILE_LENGTH = 500_000
    }

    override fun checkFile(file: PsiFile, manager: InspectionManager, isOnTheFly: Boolean): Array<ProblemDescriptor>? {
        if (file.text.length > MAX_FILE_LENGTH) return null
        if (file !is PsiJavaFile) return null

        val hits = JavaSsrfSinkFinder.findAll(file)
        if (hits.isEmpty()) return null

        val problems = hits.map { hit ->
            manager.createProblemDescriptor(
                hit.anchor,
                messageFor(hit),
                isOnTheFly,
                emptyArray(),
                ProblemHighlightType.GENERIC_ERROR_OR_WARNING,
            )
        }

        val path = file.virtualFile?.path
        if (path != null) {
            for (hit in hits) {
                val lineNumber = file.viewProvider.document?.getLineNumber(hit.anchor.textRange.startOffset) ?: -1
                ReviewPrompt.recordHit(file.project, "$path:$lineNumber")
            }
        }

        return problems.toTypedArray()
    }

    private fun messageFor(hit: SsrfSinkHit): String {
        val sinkName = when (hit.kind) {
            HttpSinkKind.JAVA_HTTP_CLIENT -> "HttpRequest.newBuilder(...)"
            HttpSinkKind.REST_TEMPLATE -> "RestTemplate"
            HttpSinkKind.OKHTTP -> "OkHttp Request.Builder"
        }
        return "$sinkName builds a request URL/host directly from '${hit.taintedSourceName}', an untrusted controller " +
            "parameter, with no allowlist check in this method -- the server can be made to proxy requests to " +
            "internal resources (CWE-918, Server-Side Request Forgery)"
    }
}
