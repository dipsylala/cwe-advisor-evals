package cases.upload;

import java.io.IOException;
import java.nio.file.Path;
import org.springframework.web.multipart.MultipartFile;

public class AvatarStorage {
    private final Path storageDir;

    public AvatarStorage(Path storageDir) {
        this.storageDir = storageDir;
    }

    public String store(MultipartFile avatar) throws IOException {
        Path target = storageDir.resolve(avatar.getOriginalFilename());
        avatar.transferTo(target);
        return target.getFileName().toString();
    }
}
