const express = require('express')
const router = express.Router()
const userController = require('../../src/controller/userController/userController')
const verifyJwt = require('../../src/middleware/verifyJWT')


router.use(verifyJwt)

router.route('/findall')
    .get(userController.getAllUsers)

router.route('/findbyUsername')
    .get(userController.getUserByUsername)

router.route('/register')
    .post(userController.createNewUser)

router.route('/update')
    .patch(userController.updateUser)
    .put(userController.updateUser)

router.route('/delete')
    .delete(userController.deleteUser)

module.exports = router