const createCRUDController = require("../middlewareController/createCRUDController");

const List = require("./list");

function modelController() {
  const Model = require("../../models/app/Product");
  const methods = createCRUDController("Product");

  methods.list = (req, res) => List(Model, req, res);
  return methods;
}

module.exports = modelController();
