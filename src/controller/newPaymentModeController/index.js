const createCRUDController = require("../middlewareController/createCRUDController");

const listAllPaymentMode = require("./listAllPaymentMode");
const createPaymentMode = require("./createPaymentMode");
const removePaymentMode = require("./RemovePaymentMode");

function modelController() {
  const Model = require("../../models/app/PaymentMode");
  const methods = createCRUDController("PaymentMode");

  methods.listAll = (req, res) => listAllPaymentMode(Model, req, res);
  methods.list = (req, res) => listAllPaymentMode(Model, req, res);
  methods.create = (req, res) => createPaymentMode(Model, req, res);
  methods.delete = (req, res) => removePaymentMode(Model, req, res);
  //  methods.update = (req, res) => update(Model, req, res);
  //   methods.delete = (req, res) => remove(Model, req, res);

  return methods;
}

module.exports = modelController();
