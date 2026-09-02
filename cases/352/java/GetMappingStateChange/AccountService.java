package com.example.accounts.service;

import org.springframework.stereotype.Service;

@Service
public class AccountService {

    public void updateEmail(String username, String newEmail) {
        // persists the new email address for the given user
    }

    public void deleteAccount(String username) {
        // deactivates and schedules deletion of the given user's account
    }
}
