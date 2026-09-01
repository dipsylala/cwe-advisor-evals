package cases.deserialize;

import java.util.Base64;

public class SessionRestoreController {
    private final SessionDecoder decoder;

    public SessionRestoreController(SessionDecoder decoder) {
        this.decoder = decoder;
    }

    public RestoredSession restore(String encodedSession) {
        byte[] payload = Base64.getDecoder().decode(encodedSession);
        return decoder.decode(payload);
    }
}

record RestoredSession(String userId, String cartId) {}
