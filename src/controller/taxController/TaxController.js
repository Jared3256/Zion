const createCRUDController = require("../middlewareController/createCRUDController");

const deleteTax = require("./deleteTax");
const updateTax = require("./updateTax");
const createTax = require("./createTax");

function taxModelController() {
  const Model = require("../../models/app/Taxes");
  const methods = createCRUDController("Taxes");

  methods.create = (req, res) => createTax(Model, req, res);
  methods.delete = (req, res) => deleteTax(Model, req, res);
  methods.update = (req, res) => updateTax(Model, res, res);
  return methods;
}
module.exports = taxModelController();
