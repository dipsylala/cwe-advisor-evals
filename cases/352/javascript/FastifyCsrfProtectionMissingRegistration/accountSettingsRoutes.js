'use strict'

const fastify = require('fastify')({ logger: true })
const fastifyCookie = require('@fastify/cookie')
const fastifySession = require('@fastify/session')

const accountStore = require('./accountStore')

// Cookie parsing and session support are registered, so every request from
// an authenticated browser carries the session cookie automatically.
fastify.register(fastifyCookie)
fastify.register(fastifySession, {
  secret: process.env.SESSION_SECRET,
  cookie: { secure: true, httpOnly: true, sameSite: 'lax' },
  saveUninitialized: false
})

// @fastify/csrf-protection is never registered in this plugin chain, and no
// route below adds its own CSRF token generation or verification hook.

function requireAuthenticatedUser(request, reply, done) {
  if (!request.session || !request.session.userId) {
    reply.code(401).send({ error: 'authentication required' })
    return
  }
  done()
}

async function updateSettingsHandler(request, reply) {
  const userId = request.session.userId
  const { displayName, email, notificationsEnabled } = request.body || {}

  if (!displayName || !email) {
    reply.code(400).send({ error: 'displayName and email are required' })
    return
  }

  // SAST FINDING: CWE-352 (Cross-Site Request Forgery) reported here. Sink is the next statement.
  const updated = await accountStore.updateAccountSettings(userId, {
    displayName,
    email,
    notificationsEnabled: Boolean(notificationsEnabled)
  })

  reply.code(200).send({ status: 'updated', account: updated })
}

fastify.post(
  '/account/settings',
  { preHandler: requireAuthenticatedUser },
  updateSettingsHandler
)

module.exports = fastify
