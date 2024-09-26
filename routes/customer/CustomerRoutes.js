const express = require('express')
const router = express.Router()
const CustomerController = require('../../src/controller/customerController/CustomerController')
const verifyJWT = require('../../src/middleware/verifyJWT')

// router.use(verifyJWT);

router.route("/findall")
    .get(CustomerController.getAllCustomers)

router.route('/findById')
    .get(CustomerController.getCustomerByEmailID)

router.route('/register')
    .post(CustomerController.registerCustomer)

router.route('/remove')
    .delete(CustomerController.deleteCustomer)

router.route('/update')
    .patch(CustomerController.updateCustomer)
    .put(CustomerController.updateCustomer)


module.exports  = router