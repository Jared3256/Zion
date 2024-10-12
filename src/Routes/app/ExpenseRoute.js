const express = require("express");
const expenseController = require("../../controller/expenseController/expenseController");
const router = express.Router();

// router.route("/list").get(expenseController.list);
router.route("/list").get(expenseController.listAll);
router.route("/listAll").get(expenseController.listAll);
router.route("/create").post(expenseController.create);
router.route("/delete/:id").delete(expenseController.delete);
router.route("/update/:id").put(expenseController.update);
router.route("/summary").get(expenseController.summary);

module.exports = router;
