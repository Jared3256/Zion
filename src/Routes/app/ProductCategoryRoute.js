const express = require("express");
const router = express.Router();
const { hasPermission } = require("../../middleware/hasPermission");
const productCategoryController = require("../../controller/productCategoryController/productCategoryController");

router
  .route("/list")
  .get(hasPermission("read"), productCategoryController.findModel);

router
  .route("/create")
  .post(hasPermission("create"), productCategoryController.createModel);

router
  .route("/delete/:id")
  .delete(hasPermission("delete"), productCategoryController.deleteModel);
router
  .route("/update/:id")
  .patch(hasPermission("update"), productCategoryController.updateModel);
module.exports = router;
