const express = require("express");
const router = express.Router();
const invoiceController = require("../../controller/invoiceController/invoiceController");

router.route("/create").post(invoiceController.create);

router.route("/list").get(invoiceController.list);

router.route("/listAll").get(invoiceController.listAll);

router.route("/update/:id").get(invoiceController.update);

router.route("/summary").get(invoiceController.summary);

router.route("/delete:id").delete(invoiceController.delete);

router.route("/search").search(invoiceController.search);

module.exports = router;
