const express = require("express");

const router = express.Router();
const clientController = require("../../controller/clientController");

router.route("/list/:id").get(clientController.list);

router.route("/listAll").get(clientController.listAll);

router.route("/search").get(clientController.search);

router.route("/summary").get(clientController.summary);

router.route("/update/:id").put(clientController.update);

router.route("/create").post(clientController.create);

router.route("/delete:/id").delete(clientController.delete);

module.exports = router;
