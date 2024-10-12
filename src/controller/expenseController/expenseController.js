const Model = require("../../models/app/Expense");

const createCRUDController = require("../../controller/middlewareController/createCRUDController");

function expenseController() {
  const methods = createCRUDController("Expense");

  return methods;
}

module.exports = expenseController();
