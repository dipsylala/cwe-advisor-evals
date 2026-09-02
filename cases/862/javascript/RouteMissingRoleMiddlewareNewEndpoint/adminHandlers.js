const User = require('./userStore');

async function banUserHandler(req, res) {
  const user = await User.findByIdAndUpdate(req.params.id, { banned: true });
  res.json({ id: user.id, banned: true });
}

async function unbanUserHandler(req, res) {
  const user = await User.findByIdAndUpdate(req.params.id, { banned: false });
  res.json({ id: user.id, banned: false });
}

async function deleteUserHandler(req, res) {
  await User.findByIdAndDelete(req.params.id);
  res.status(204).end();
}

// Returns every user's profile, email, and billing history as a single
// JSON payload - any authenticated caller can currently trigger this.
async function exportUsersHandler(req, res) {
  const users = await User.find({}).select('+email +billingHistory');
  res.json(users);
}

module.exports = { banUserHandler, unbanUserHandler, deleteUserHandler, exportUsersHandler };
