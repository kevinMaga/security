var express = require("express");
var router = express.Router();
/* 1. Importe el módulo crypto */
let crypto = require("crypto");
/* 2. Cargue los modelos de acuerdo con la configuración de la conexión */
const sequelize = require("../models/index.js").sequelize;
var initModels = require("../models/init-models");
var models = initModels(sequelize);

/* GET home page. */
router.get("/", function (req, res, next) {
  res.render("index", { title: "Express" });
});

/* POST user. */
/* 3. Cree el callback asíncrono que responda al método POST */
/* POST user. */
router.post("/login", async function (req, res, next) {
  let { username, password } = req.body;

  if (username != null && password != null) {
    try {
      let userData = await models.users.findOne({
        where: { name: username },
        include: { all: true, nested: true },
        raw: true,
        nest: true
      });

      if (userData != null && userData.password != null) {
        let salt = userData.password.split("$")[0];
        let hash = crypto
          .createHmac("sha512", salt)
          .update(password)
          .digest("base64");
        let passwordHash = salt + "$" + hash;

        if (passwordHash === userData.password) {
          const options = {
            expires: new Date(Date.now() + 60 * 1000),
          };
          res.cookie("username", username, options);
          req.session.loggedin = true;
          req.session.username = username;
          req.session.role = userData.users_roles.roles_idrole_role.name;

          // Redirige según el rol
          if (req.session.role === 'Administrator') {
            res.redirect("/token");
          } else {
            res.redirect("/users");
          }
        } else {
          res.redirect("/");
        }
      } else {
        res.redirect("/");
      }
    } catch (error) {
      res.status(400).send(error);
    }
  } else {
    res.redirect("/");
  }
});
/* GET logout. */
/* 2. Método para terminar la sesión */
router.get("/logout", function (req, res, next) {
  req.session.destroy();
  res.render("index");
});

module.exports = router;