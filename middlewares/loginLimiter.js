const rateLimit = require('express-rate-limit')

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { msg: 'Muitas tentativas de login. Tente novamente mais tarde.' }
})

module.exports = loginLimiter