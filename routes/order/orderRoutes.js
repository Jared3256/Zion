const express = require('express')
const router = express.Router()
const orderController = require('../../src/controller/orderController/OrderController')
const verifyJwt = require('../../src/middleware/verifyJWT')

// protect all the routes under orders
router.use(verifyJwt)

router.route('/findall')
    .get(orderController.getAllOrders)

router.route("/findall/email")
    .get(orderController.getAllOrderByEmail)
    
router.route("/findbyId")
    .get(orderController.getOrderById)

router.route('/create')
    .post(orderController.createOrder)

router.route('/update')
    .patch(orderController.updateOrder)
    .put(orderController.updateOrder)
router.route('/remove')
    .delete(orderController.deleteOrder)

module.exports = router