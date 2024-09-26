const express = require("express");
const router = express.Router();
const { hasPermission } = require("../../middleware/hasPermission");
const currencyController = require("../../controller/currencyController");

router.route("/listAll").get(hasPermission("read"), currencyController.listAll);

router.route("/list").get(currencyController.listAll);

router
  .route("/create")
  .post(hasPermission("create"), currencyController.create);

router
  .route("/delete/:id")
  .delete(hasPermission("delete"), currencyController.delete);
router
  .route("/update/:id")
  .patch(hasPermission("update"), currencyController.update);
module.exports = router;
