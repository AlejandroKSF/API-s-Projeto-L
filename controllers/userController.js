const User = require('../models/User')

async function getUserById(req, res) {
  const id = req.params.id

  try {
    const user = await User.findById(id, '-password') // exclude password field

    //check if user exists
    if (!user) {
      return res.status(404).json({ msg: 'Usuário não encontrado' })
    }

    res.status(200).json({ user })
  } catch (err) {
    console.error(err)
    res.status(500).json({ msg: 'Erro no servidor' })
  }
}



module.exports = {
  getUserById,
}
