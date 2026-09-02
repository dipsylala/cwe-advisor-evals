'use strict';

class AccountStore {
  constructor() {
    this.accounts = new Map();
  }

  updateEmail(userId, email) {
    const account = this.accounts.get(userId) || {};
    account.email = email;
    this.accounts.set(userId, account);
    return account;
  }

  updatePassword(userId, newPassword) {
    const account = this.accounts.get(userId) || {};
    account.passwordHash = `hashed:${newPassword}`;
    this.accounts.set(userId, account);
    return account;
  }
}

module.exports = { AccountStore };
