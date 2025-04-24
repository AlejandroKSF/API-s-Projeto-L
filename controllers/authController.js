const User = require('../models/User')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const axios = require('axios')

// user register
async function register(req, res) {
  const { name, email, password, confirmpassword } = req.body

  if (!name || !email || !password) {
    return res.status(422).json({ msg: 'Nome, email e senha são obrigatórios' })
  }

  if (password !== confirmpassword) {
    return res.status(422).json({ msg: 'As senhas não conferem' })
  }

  const userExists = await User.findOne({ email })
  if (userExists) {
    return res.status(422).json({ msg: 'Por favor, utilize outro e-mail!' })
  }

  const salt = await bcrypt.genSalt(12)
  const passwordHash = await bcrypt.hash(password, salt)

  const user = new User({ name, email, password: passwordHash })

  try {
    await user.save()
    res.status(201).json({ msg: 'Usuário criado com sucesso!' })
  } catch (error) {
    console.log(error)
    res.status(500).json({ msg: 'Erro no servidor' })
  }
}

// LOGIN
async function login(req, res) {
    const { email, password, captchaToken } = req.body
  
    if (!email || !password || !captchaToken) {
      return res.status(422).json({ msg: 'Email, senha e captcha são obrigatórios' })
    }
  
    // Recaptcha

    
    try {
      const { data } = await axios.post(`https://www.google.com/recaptcha/api/siteverify`, null, {
        params: {
          secret: process.env.RECAPTCHA_SECRET,
          response: captchaToken,
        },
      })
  
      const { success, score, action } = data
  
      if (!success || score < 0.5 || action !== 'login') {
        return res.status(403).json({ msg: 'reCAPTCHA suspeito. Tente novamente.' })
      }
    } catch (err) {
      console.error(err)
      return res.status(500).json({ msg: 'Erro ao verificar reCAPTCHA' })
    }
      
    // User/password verify
    const user = await User.findOne({ email })
  
    // invalid user
    if (!user) {
      return res.status(404).json({ msg: 'Usuário e/ou senha inválida' })
    }
  
    //check if password match
    const checkPassword = await bcrypt.compare(password, user.password)

    // invalid password
    if (!checkPassword) {
      return res.status(422).json({ msg: 'Usuário e/ou senha inválida' })
    }
  
    try {
      const secret = process.env.SECRET
  
      const token = jwt.sign({ id: user._id }, secret, {
        expiresIn: process.env.JWT_EXPIRES,
      })
  
      const refreshToken = jwt.sign({ id: user._id }, secret, {
        expiresIn: process.env.REFRESHJWT_EXPIRES,
      })
  
      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: false,
        sameSite: 'Strict',
        maxAge: 2 * 24 * 60 * 60 * 1000,
      })
  
      res.status(200).json({ msg: 'Autenticação realizada com sucesso', token })
    } catch (error) {
      console.log(error)
      res.status(500).json({ msg: 'Erro no servidor' })
    }
}

// Logout
function logout(req, res) {
  res.clearCookie('refreshToken', {
    httpOnly: true,
    secure: false,
    sameSite: 'Strict',
  })
  res.status(200).json({ msg: 'Logout realizado com sucesso' })
}

// Refresh token
function refreshToken(req, res) {
  const token = req.cookies.refreshToken

  if (!token) {
    return res.status(401).json({ msg: 'Refresh token ausente' })
  }

  try {
    const secret = process.env.SECRET
    const decoded = jwt.verify(token, secret)

    const newToken = jwt.sign({ id: decoded.id }, secret, {
      expiresIn: process.env.JWT_EXPIRES,
    })

    return res.status(200).json({ accessToken: newToken })
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(403).json({ msg: 'Refresh Token expirado. Faça login novamente.' })
    }
    return res.status(403).json({ msg: 'Refresh token inválido' })
  }
}

module.exports = {
  register,
  login,
  logout,
  refreshToken,
}
