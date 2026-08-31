package evalcases;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;

@RestController
public class MultipartUploadNoValidation {

    private static final String UPLOAD_DIR = "/var/www/html/uploads/";

    @PostMapping("/upload")
    public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
        String originalFilename = file.getOriginalFilename();
        File destination = new File(UPLOAD_DIR + originalFilename);
        // SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
        file.transferTo(destination);
        return "Uploaded to " + destination.getAbsolutePath();
    }
}
