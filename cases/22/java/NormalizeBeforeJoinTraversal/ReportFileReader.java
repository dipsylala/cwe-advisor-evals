package cases.pathtraversal;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class ReportFileReader {
    private static final Path BASE_DIR = Path.of("/var/app-data/reports");

    public byte[] readReport(String userSuppliedPath) throws IOException {
        String cleaned = Path.of(userSuppliedPath).normalize().toString();
        Path target = BASE_DIR.resolve(cleaned);

        // SAST FINDING: CWE-22 (Path Traversal) reported here. Sink is the next statement.
        return Files.readAllBytes(target);
    }
}
