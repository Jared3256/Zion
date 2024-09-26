const express = require('express')
const router = express.Router()
const authController = require('../../src/controller/authController/authController')
const loginLimiter = require('../../src/middleware/loginLimiter')

router.route('/code')
    .post(loginLimiter, authController.ResetCodePass)

router.route("/reset")
    .post(authController.ResetPassword)

router.route('/login')
    .post(loginLimiter,authController.login)

router.route('/refresh')
    .get(authController.refresh)

router.route('/logout')
    .post(authController.logout)

module.exports = router