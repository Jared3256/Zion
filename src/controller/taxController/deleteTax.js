const asyncHandler = require("express-async-handler");

const deleteTaxModel = asyncHandler(async (Model, req, res) => {
  return res.status(403).json({
    success: false,
    result: null,
    message: "you can't delete tax after it has been created",
  });
});

module.exports = deleteTaxModel;
