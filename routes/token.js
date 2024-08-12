var jwt = require('jsonwebtoken');
var express = require('express');
var router = express.Router();

router.get('/', async function(req, res, next) {
var token =   await jwt.sign({
    exp: Math.floor(Date.now() / 1000) + (60 * 60),
    data: 'foobar'
  }, 'secret');

    res.render('token', { title: 'Express', tk: token});
  });

 module.exports = router;