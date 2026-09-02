package cases.upload;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

public class AvatarStorage {
    private static final Path STORAGE_ROOT = Path.of("/var/app-data/avatars");

    // detectedType has already been validated by the caller against an allowlist of
    // image/png, image/jpeg, image/svg+xml, detected from the file's actual bytes.
    public String store(byte[] bytes, String detectedType) throws IOException {
        String storedName = UUID.randomUUID() + extensionFor(detectedType);
        Files.write(STORAGE_ROOT.resolve(storedName), bytes);
        return storedName;
    }

    static String extensionFor(String detectedType) {
        return switch (detectedType) {
            case "image/png" -> ".png";
            case "image/jpeg" -> ".jpg";
            case "image/svg+xml" -> ".svg";
            default -> throw new IllegalArgumentException("Unsupported type");
        };
    }
}
