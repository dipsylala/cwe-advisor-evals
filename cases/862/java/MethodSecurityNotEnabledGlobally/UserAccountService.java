package com.example.accounts;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

@Service
public class UserAccountService {

    private final UserAccountRepository userAccountRepository;

    public UserAccountService(UserAccountRepository userAccountRepository) {
        this.userAccountRepository = userAccountRepository;
    }

    @PreAuthorize("hasRole('ADMIN')")
    public void deleteUserAccount(long userId) {
        // SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
        userAccountRepository.deleteById(userId);
    }

    @PreAuthorize("hasRole('ADMIN')")
    public void suspendUserAccount(long userId) {
        UserAccount account = userAccountRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown user " + userId));
        account.setSuspended(true);
        userAccountRepository.save(account);
    }
}
