package cases.xss;

import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

public class AnnouncementController {
    private final AnnouncementService service;

    public AnnouncementController(AnnouncementService service) {
        this.service = service;
    }

    @GetMapping("/announcements/preview")
    public String preview(@RequestParam String draftId, Model model) {
        model.addAttribute("announcement", service.loadDraft(draftId));
        return "announcement-preview";
    }
}
