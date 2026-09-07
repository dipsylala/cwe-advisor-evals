// Compile-only collaborator the fixture requires but does not ship (evals/stubs).
const mongoose = require('mongoose');
const schema = new mongoose.Schema({ username: String, passwordHash: String });
module.exports = mongoose.model('User', schema);
