var express = require('express');
var router = express.Router();
let crypto = require('crypto');

// Cargue los modelos de acuerdo con la configuración de la conexión
const sequelize = require('../models/index.js').sequelize;
var initModels = require("../models/init-models");
var models = initModels(sequelize);

/* GET home page. */
router.get('/', function (req, res, next) {
  res.render('index', { title: 'Express' });
});

router.post('/login', async function (req, res, next) {

  // Desestructure los elementos en el cuerpo del requerimiento
  let { username, password } = req.body;

  // Verifique que username sea diferente de null, y que password sea diferente de null.
  if (username != null && password != null) {

    try {
      // Del modelo users, use el método findOne para encontrar un registro cuyo campo name sea igual que username
      let userData = await models.users.findOne({
        where: { name: username },
        include: { all: true, nested: true },
        raw: true,
        nest: true
      });

      // Verifique que userData sea diferente de null, y que userData.password sea diferente de null.
      if (userData != null && userData.password != null) {

        // Divida userData.password por el símbolo "$", y use el primer elemento como SALT.
        let salt = userData.password.split("$")[0];
        let hash = crypto.createHmac('sha512', salt).update(password).digest("base64");
        let passwordHash = salt + "$" + hash;

        // Compare passwordHash y userData.password que sean iguales.
        if (passwordHash === userData.password) {
          // Configuración de la sesión
          req.session.loggedin = true;
          req.session.username = username;
          req.session.role = userData.users_roles.roles_idrole_role.name;

          // Redirección basada en el rol del usuario
          if (process.env.ALL_GRANTED.includes(req.session.role)) {
            return res.redirect('/users'); // Página para roles con acceso completo
          } else if (process.env.ALL_USER.includes(req.session.role)) {
            return res.redirect('/token'); // Página para roles con acceso limitado
          } else {
            return res.redirect('/'); // Redirección a la página de inicio si el rol no es válido
          }
        } else {
          // En caso de fallo en la comparación de contraseñas, redirige a '/'
          res.redirect('/');
        }
      } else {
        // En caso de no encontrar datos del usuario o la contraseña sea null, redirige a '/'
        res.redirect('/');
      }

    } catch (error) {
      // En caso de error, retorne el estado 400 y el objeto error
      res.status(400).send(error);
    }
  } else {
    // Redirige a '/' si username o password son null
    res.redirect('/');
  }
});

/* GET logout. */
/* Método para terminar la sesión */
router.get('/logout', function (req, res, next) {
  req.session.destroy();
  res.render('index');
});

module.exports = router;
