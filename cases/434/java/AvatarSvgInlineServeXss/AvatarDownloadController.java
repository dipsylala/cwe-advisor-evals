package cases.upload;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AvatarDownloadController {
    private static final Path STORAGE_ROOT = Path.of("/var/app-data/avatars");

    @GetMapping("/api/avatars/{storedName}")
    public ResponseEntity<byte[]> download(@PathVariable String storedName) throws IOException {
        byte[] bytes = Files.readAllBytes(STORAGE_ROOT.resolve(storedName));
        String contentType = storedName.endsWith(".svg") ? "image/svg+xml" : "image/*";

        // SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
        return ResponseEntity.ok().header(HttpHeaders.CONTENT_TYPE, contentType).body(bytes);
    }
}
