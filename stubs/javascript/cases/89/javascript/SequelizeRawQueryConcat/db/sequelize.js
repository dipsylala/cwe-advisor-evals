// Compile-only collaborator the fixture requires but does not ship (evals/stubs).
const { Sequelize } = require('sequelize');
module.exports = new Sequelize('sqlite::memory:', { logging: false });
