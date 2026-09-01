package cases.xss;

public class AnnouncementService {
    public AnnouncementDraft loadDraft(String draftId) {
        return new AnnouncementDraft("Maintenance", "<p>Draft body</p>");
    }
}

record AnnouncementDraft(String title, String bodyHtml) {}
