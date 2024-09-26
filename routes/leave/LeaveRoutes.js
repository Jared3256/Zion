const express = require('express')
const router = express.Router()
const LeaveController = require('../../src/controller/leaveController/LeaveController')
const verifyJwt = require('../../src/middleware/verifyJWT')

// lock access to the the routes by jwt
router.use(verifyJwt)

router.route("/find/all")
    .get(LeaveController.getAllLeaveRequest)

router.route('/find/all/email')
    .get(LeaveController.getAllLeaveByEmail)

router.route('/apply')
    .post(LeaveController.applyForLeave)

router.route('/manage')
    .patch(LeaveController.manageLeave)
    .put(LeaveController.manageLeave)

router.route('/adjust')
    .put(LeaveController.adjustLeave)

router.route('/remove')
    .delete(LeaveController.deleteLeave)

module.exports = router
