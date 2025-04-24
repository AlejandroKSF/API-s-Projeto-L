require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const cors = require('cors')
const cookieParser = require('cookie-parser')

const authRoutes = require('./routes/auth')
const userRoutes = require('./routes/user')
const connectDB = require('./config/db')

const app = express()

app.use(express.json())
app.use(cookieParser())
app.use(cors({ origin: ['http://localhost:5173'], credentials: true }))

app.use('/auth', authRoutes)
app.use('/user', userRoutes)

app.get('/', (req, res) => res.status(200).json({ msg: 'TESTE' }))

connectDB().then(() => {
  app.listen(3000, () => console.log('Servidor rodando na porta 3000'))
})