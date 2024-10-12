const express = require("express");
const router = express.Router();
const { hasPermission } = require("../../middleware/hasPermission");
const productController = require("../../controller/productController");
const verifyJwt = require("../../middleware/verifyJWT");

router.use(verifyJwt);

router.route("/list").get(hasPermission("read"), productController.listAll);

router.route("/create").post(hasPermission("create"), productController.create);

router
  .route("/delete/:id")
  .delete(hasPermission("delete"), productController.delete);
router
  .route("/update/:id")
  .patch(hasPermission("update"), productController.update);
module.exports = router;
