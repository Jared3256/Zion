const express = require("express");
const router = express.Router();
const TaxController = require("../../controller/taxController/TaxController");
// const { hasPermission } = require("../../middleware/hasPermission");
// const verifyJwt = require("../../middleware/verifyJWT");

router.route("/create").post(TaxController.create);

router.route("/delete/:id").delete(TaxController.delete);

router.route("/update/:id").put(TaxController.update);

router.route("/list").get(TaxController.list);

router.route("/listAll").get(TaxController.listAll);

router.route("/summary").get(TaxController.summary);

router.route("/search/:id").get(TaxController.search);

router.route("/filter").get(TaxController.filter);

module.exports = router;
