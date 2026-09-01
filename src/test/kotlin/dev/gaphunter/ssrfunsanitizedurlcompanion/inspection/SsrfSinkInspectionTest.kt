package dev.gaphunter.ssrfunsanitizedurlcompanion.inspection

import com.intellij.testFramework.fixtures.BasePlatformTestCase

class SsrfSinkInspectionTest : BasePlatformTestCase() {

    override fun setUp() {
        super.setUp()
        myFixture.enableInspections(SsrfSinkInspection::class.java)
    }

    fun `test HttpClient newBuilder with a tainted URI is flagged`() {
        myFixture.configureByText(
            "FetchController.java",
            """
            import java.net.URI;
            import java.net.http.HttpRequest;
            import org.springframework.web.bind.annotation.GetMapping;

            class FetchController {
                @GetMapping("/fetch")
                void fetch(String targetUrl) {
                    HttpRequest.newBuilder(URI.create(targetUrl));
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.any { it.description?.contains("Server-Side Request Forgery") == true })
    }

    fun `test RestTemplate getForObject with a tainted url is flagged`() {
        myFixture.configureByText(
            "FetchController2.java",
            """
            import org.springframework.web.bind.annotation.GetMapping;
            import org.springframework.web.client.RestTemplate;

            class FetchController2 {
                private final RestTemplate restTemplate = new RestTemplate();

                @GetMapping("/fetch2")
                String fetch(String targetUrl) {
                    return restTemplate.getForObject(targetUrl, String.class);
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.any { it.description?.contains("Server-Side Request Forgery") == true })
    }

    fun `test OkHttp Request Builder url with a tainted value is flagged`() {
        myFixture.configureByText(
            "FetchController3.java",
            """
            import okhttp3.Request;
            import org.springframework.web.bind.annotation.GetMapping;

            class FetchController3 {
                @GetMapping("/fetch3")
                void fetch(String targetUrl) {
                    Request request = new Request.Builder().url(targetUrl).build();
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.any { it.description?.contains("Server-Side Request Forgery") == true })
    }

    fun `test a validated URL is not flagged`() {
        myFixture.configureByText(
            "SafeController.java",
            """
            import java.net.URI;
            import java.net.http.HttpRequest;
            import org.springframework.web.bind.annotation.GetMapping;

            class SafeController {
                @GetMapping("/safe")
                void fetch(String targetUrl) {
                    if (!isAllowedHost(targetUrl)) throw new RuntimeException("blocked");
                    HttpRequest.newBuilder(URI.create(targetUrl));
                }

                private boolean isAllowedHost(String url) {
                    return true;
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.none { it.description?.contains("Server-Side Request Forgery") == true })
    }

    fun `test a non-endpoint method is never flagged even with the same shape`() {
        myFixture.configureByText(
            "PlainHelper.java",
            """
            import java.net.URI;
            import java.net.http.HttpRequest;

            class PlainHelper {
                void fetch(String targetUrl) {
                    HttpRequest.newBuilder(URI.create(targetUrl));
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.none { it.description?.contains("Server-Side Request Forgery") == true })
    }

    fun `test a fixed internal URL unrelated to any parameter is not flagged`() {
        myFixture.configureByText(
            "InternalController.java",
            """
            import java.net.URI;
            import java.net.http.HttpRequest;
            import org.springframework.web.bind.annotation.GetMapping;

            class InternalController {
                @GetMapping("/internal")
                void fetch(String unrelatedParam) {
                    HttpRequest.newBuilder(URI.create("https://internal.example.com/health"));
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.none { it.description?.contains("Server-Side Request Forgery") == true })
    }
}
