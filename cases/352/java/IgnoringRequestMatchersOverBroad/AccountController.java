package cases.csrf;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

// Authenticated account-management endpoints under /api/. Because SecurityConfig's
// CSRF exclusion is patterned on "/api/**" instead of "/api/webhooks/**", this
// controller's session-cookie-authenticated, state-changing routes are reachable
// without a CSRF token from any origin.
@RestController
@RequestMapping("/api/account")
public class AccountController {

    private final AccountService accountService;

    public AccountController(AccountService accountService) {
        this.accountService = accountService;
    }

    @PostMapping("/email")
    public AccountResult changeEmail(Authentication authentication, @RequestBody EmailChangeRequest request) {
        String userId = authentication.getName();
        accountService.updateEmail(userId, request.newEmail());
        return new AccountResult("updated");
    }

    public record EmailChangeRequest(String newEmail) {
    }

    public record AccountResult(String status) {
    }

    public interface AccountService {
        void updateEmail(String userId, String newEmail);
    }
}
