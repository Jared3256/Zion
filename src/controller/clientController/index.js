const Model = require("../../models/app/Client");
const createCRUDController = require("../../controller/middlewareController/createCRUDController");

const create = require("./create");
const listAll = require("./listAll");
const paginatedList = require("./paginatedList");
const read = require("./read");
const remove = require("./remove");
const search = require("./search");
const summary = require("./summary");
const update = require("./update");

function clientController() {
  const methods = createCRUDController("Client");

  methods.create = (req, res) => create(Model, req, res);
  methods.listAll = (req, res) => listAll(Model, req, res);
  methods.paginatedList = (req, res) => paginatedList(Model, req, res);
  methods.read = (req, res) => read(Model, req, res);
  methods.remove = (req, res) => remove(Model, req, res);
  methods.search = (req, res) => search(Model, req, res);
  methods.summary = (req, res) => search(Model, req, res);
  methods.update = (req, res) => update(Model, req, res);

  return methods;
}

module.exports = clientController();
