const asyncHandler = require("express-async-handler");

const update = asyncHandler(async (Model, req, res) => {
  return res.status(200).json({
    success: false,
    result: null,
    message: "You cant update client once is created",
  });
});

module.exports = update;
