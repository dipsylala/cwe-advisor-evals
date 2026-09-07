// Compile-only collaborator the fixture requires but does not ship (evals/stubs).
const mongoose = require('mongoose');
const schema = new mongoose.Schema({ username: String, banned: Boolean, email: { type: String, select: false }, billingHistory: { type: Array, select: false } });
module.exports = mongoose.model('User', schema);
