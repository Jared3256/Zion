const express = require("express");
const router = express.Router();
const { hasPermission } = require("../../middleware/hasPermission");
const paymentModeController = require("../../controller/paymentModeController/paymentModeController");

router
  .route("/list")
  .get(hasPermission("read"), paymentModeController.findModel);

router
  .route("/create")
  .post(hasPermission("create"), paymentModeController.createModel);

router
  .route("/delete/:id")
  .delete(hasPermission("delete"), paymentModeController.deleteModel);
router
  .route("/update/:id")
  .patch(hasPermission("update"), paymentModeController.updateModel);
module.exports = router;
