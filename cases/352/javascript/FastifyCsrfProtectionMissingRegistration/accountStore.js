'use strict'

const accounts = new Map()

async function updateAccountSettings(userId, settings) {
  const existing = accounts.get(userId) || { userId }
  const account = { ...existing, ...settings, updatedAt: new Date().toISOString() }
  accounts.set(userId, account)
  return account
}

module.exports = { updateAccountSettings }
