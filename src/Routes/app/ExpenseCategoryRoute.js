const express = require("express");
const expenseCategoryController = require("../../controller/expenseCategoryController/expenseCategoryCategory");

const router = express.Router();

router.route("/list").get(expenseCategoryController.list);
router.route("/listAll").get(expenseCategoryController.listAll);
router.route("/create").post(expenseCategoryController.create);
router.route("/delete/:id").delete(expenseCategoryController.delete);
router.route("/update/:id").put(expenseCategoryController.update);
router.route("/summary").get(expenseCategoryController.summary);
router.route("/search").get(expenseCategoryController.search);

module.exports = router;
