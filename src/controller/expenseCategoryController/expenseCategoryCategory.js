const Model = require("../../models/app/ExpenseCategory");

const createCRUDController = require("../../controller/middlewareController/createCRUDController");

function expenseCategoryController() {
  const methods = createCRUDController("ExpenseCategory");

  return methods;
}

module.exports = expenseCategoryController();
