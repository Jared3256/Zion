const asyncHandler = require("express-async-handler");

const createTaxModel = asyncHandler(async (Model, req, res) => {
  const { isDefault } = req.body;

  if (isDefault) {
    await Model.updateMany({}, { isDefault: false });
  }

  const countDefault = await Model.countDocuments({
    isDefault: true,
  });

  const result = await new Model({
    ...req.body,

    isDefault: countDefault < 1 ? true : false,
  }).save();

  return res.status(200).json({
    success: true,
    result: result,
    message: "Tax created successfully",
  });
});

module.exports = createTaxModel;
