const createCRUDController = require("../../controller/middlewareController/createCRUDController");
const Model = require("../../models/app/Invoice");

const create = require("./create");
const paginatedList = require("./paginatedList");
const read = require("./read");
const remove = require("./remove");
const summary = require("./summary");
const update = require("./update");

function invoiceController() {
  const methods = createCRUDController("Invoice");

  methods.list = (req, res) => paginatedList(Model, req, res);
  methods.create = (req, res) => create(Model, req, res);
  methods.read = (req, res) => read(Model, req, res);
  methods.remove = (req, res) => remove(Model, req, res);
  methods.summary = (req, res) => summary(Model, req, res);
  methods.update = (req, res) => update(Model, req, res);

  return methods;
}

module.exports = invoiceController();
