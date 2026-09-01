package dev.gaphunter.ssrfunsanitizedurlcompanion.detect

import com.intellij.psi.PsiAnnotation
import com.intellij.psi.PsiMethod

/**
 * A closed, known list of Spring MVC/JAX-RS annotations that mark a
 * method as an HTTP endpoint -- every parameter of such a method is
 * treated as an untrusted source (Spring/JAX-RS binds request data --
 * query params, path variables, request bodies -- directly to these
 * parameters). Deliberately a closed list of real framework
 * annotations, not an attempt at general taint-source inference.
 */
object ControllerEndpointSignals {

    private val METHOD_MAPPING_ANNOTATIONS = setOf(
        // Spring MVC
        "PostMapping", "GetMapping", "PutMapping", "DeleteMapping", "PatchMapping", "RequestMapping",
        // JAX-RS
        "POST", "GET", "PUT", "DELETE", "PATCH",
    )

    /** True when [method] is itself annotated with a known HTTP-mapping annotation (Spring MVC or JAX-RS). */
    fun isEndpointMethod(method: PsiMethod): Boolean =
        method.modifierList.annotations.any { it.simpleNameMatches(METHOD_MAPPING_ANNOTATIONS) }

    private fun PsiAnnotation.simpleNameMatches(names: Set<String>): Boolean =
        nameReferenceElement?.referenceName in names
}
