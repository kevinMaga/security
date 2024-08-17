const jwt = require('jsonwebtoken');
const express = require('express');
const router = express.Router();

const TOKEN_SECRET = process.env.TOKEN_SECRET

router.get('/', async function(req, res, next) {
  try {
    const user = {
      id: req.body.id,          
      username: req.body.username 
    }

    const payload = {
      id: user.id,
      username: user.username,
    };

    const token = jwt.sign(payload, TOKEN_SECRET, { expiresIn: '1h' });

    res.render('token', { title: 'Express', Token: token });

  } catch (error) {
    console.error('Error al generar el token:', error);
    res.status(500).json({ message: 'Error al generar el token', error: error.message });
  }
});

module.exports = router;