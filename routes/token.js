require('dotenv').config()

var express = require("express");
var router = express.Router();


const sequelize = require('../models/index.js').sequelize;
var initModels = require("../models/init-models");
var models = initModels(sequelize);

const jwt = require('jsonwebtoken');
const { TOKEN_SECRET } = process.env;


/* GET home page. */
router.get("/", function (req, res, next) {

  const payload = {
    user: {
      id: req.session.id,
      username: req.session.username
    },
    role: req.session.role
  };

  const token = jwt.sign(payload, TOKEN_SECRET, { expiresIn: '1h' });

  return res.render("token", { title: "Token user", username: req.cookies['username'], token } );
});
module.exports = router;