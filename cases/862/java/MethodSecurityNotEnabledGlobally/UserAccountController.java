package com.example.accounts;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserAccountController {

    private final UserAccountService userAccountService;

    public UserAccountController(UserAccountService userAccountService) {
        this.userAccountService = userAccountService;
    }

    @DeleteMapping("/api/admin/users/{userId}")
    public void deleteUser(@PathVariable long userId) {
        userAccountService.deleteUserAccount(userId);
    }

    @PostMapping("/api/admin/users/{userId}/suspend")
    public void suspendUser(@PathVariable long userId) {
        userAccountService.suspendUserAccount(userId);
    }
}
