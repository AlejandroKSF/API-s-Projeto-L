const mongoose = require('mongoose')

module.exports = async function connectDB() {
  try {
    const dbuser = process.env.DB_USER
    const dbpass = process.env.DB_PASS
    await mongoose.connect(`mongodb+srv://${dbuser}:${dbpass}@project-l.i1ltwh1.mongodb.net/?retryWrites=true&w=majority&appName=Project-L`)
    console.log('Database connected!')
  } catch (err) {
    console.error('Erro ao conectar no banco:', err)
    process.exit(1)
  }
}