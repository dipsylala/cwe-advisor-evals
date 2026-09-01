package cases.path;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class ZipExtractor {
    public void extract(ZipInputStream zip, Path destination) throws IOException {
        ZipEntry entry;
        while ((entry = zip.getNextEntry()) != null) {
            Path target = destination.resolve(entry.getName()).normalize();
            if (!target.startsWith(destination)) {
                throw new IOException("entry escapes destination");
            }

            Files.copy(zip, target);
        }
    }
}
