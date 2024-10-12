const createCRUDController = require("../middlewareController/createCRUDController");

const remove = require("./remove");
const update = require("./update");

function modelController() {
  const Model = require("../../models/app/Currency");
  const methods = createCRUDController("Currency");

  methods.update = (req, res) => update(Model, req, res);
  methods.delete = (req, res) => remove(Model, req, res);

  return methods;
}

module.exports = modelController();
