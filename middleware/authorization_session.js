 /* Autorización */

 var authorizationSession = (req, res, next) => {
    if(process.env.ALL_GRANTED.includes(req.session.role)) {
        return next()
    } if(process.env.ALL_USER.includes(req.session.role)) {
        return res.redirect("/token")
    } else{
        return res.redirect("/")
    }
}

module.exports = authorizationSession;