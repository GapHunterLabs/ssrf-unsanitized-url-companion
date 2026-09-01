import java.net.URI;
import java.net.http.HttpRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.client.RestTemplate;

class FetchController {

    private final RestTemplate restTemplate = new RestTemplate();

    // Flagged: targetUrl (untrusted controller parameter) used directly.
    @GetMapping("/fetch")
    void fetchWithHttpClient(String targetUrl) {
        HttpRequest.newBuilder(URI.create(targetUrl));
    }

    // Flagged: same untrusted source via RestTemplate.
    @GetMapping("/fetch2")
    String fetchWithRestTemplate(String targetUrl) {
        return restTemplate.getForObject(targetUrl, String.class);
    }

    // Not flagged: allowlist check present before the request.
    @GetMapping("/fetch-safe")
    void fetchSafe(String targetUrl) {
        if (!isAllowedHost(targetUrl)) throw new RuntimeException("blocked");
        HttpRequest.newBuilder(URI.create(targetUrl));
    }

    private boolean isAllowedHost(String url) {
        return url.startsWith("https://api.trusted-partner.com/");
    }
}
