package cases.upload;

import java.io.IOException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class AvatarController {
    private final AvatarStorage storage;

    public AvatarController(AvatarStorage storage) {
        this.storage = storage;
    }

    @PostMapping("/profile/avatar")
    public ResponseEntity<String> upload(@RequestParam MultipartFile avatar) throws IOException {
        String contentType = avatar.getContentType();
        if (!"image/png".equals(contentType) && !"image/jpeg".equals(contentType)) {
            return ResponseEntity.badRequest().body("unsupported avatar");
        }

        return ResponseEntity.ok(storage.store(avatar));
    }
}
