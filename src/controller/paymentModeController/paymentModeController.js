const asyncHandler = require("express-async-handler");

// import the payment mode model
const paymentMode = require("../../models/app/PaymentMode");

// Function for getting all PaymentModes
const findModel = asyncHandler(async (req, res) => {
  const models = await paymentMode.find();

  if (!models?.length) {
    return res.status(404).json({ message: "" });
  }
  res.json(models);
});
// Function for creating new objects
const createModel = asyncHandler(async (req, res) => {
  const { isDefault } = req.body;

  if (isDefault) {
    await paymentMode.updateMany({}, { isDefault: false });
  }

  const countDefault = await paymentMode.countDocuments({
    isDefault: true,
  });

  const result = await new paymentMode({
    ...req.body,

    isDefault: countDefault < 1 ? true : false,
  }).save();

  return res.status(200).json({
    success: true,
    result: result,
    message: "payment mode created successfully",
  });
});

const deleteModel = asyncHandler((req, res) => {
  return res.status(403).json({
    success: false,
    result: null,
    message: "you can't delete payment mode after it has been created",
  });
});

const updateModel = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const payment = await paymentMode
    .findOne({
      _id: req.params.id,
      removed: false,
    })
    .exec();
  const { isDefault = paymentMode.isDefault, enabled = paymentMode.enabled } =
    req.body;

  // if isDefault:false , we update first - isDefault:true
  // if enabled:false and isDefault:true , we update first - isDefault:true
  if (!isDefault || (!enabled && isDefault)) {
    await paymentMode.findOneAndUpdate(
      { _id: { $ne: id }, enabled: true },
      { isDefault: true }
    );
  }

  // if isDefault:true and enabled:true, we update other paymentMode and make is isDefault:false
  if (isDefault && enabled) {
    await payment.updateMany({ _id: { $ne: id } }, { isDefault: false });
  }

  const paymentModeCount = await paymentMode.countDocuments({});

  console.log(paymentModeCount);
  // if enabled:false and it's only one exist, we can't disable
  if ((!enabled || !isDefault) && paymentModeCount <= 1) {
    return res.status(422).json({
      success: false,
      result: null,
      message:
        "You cannot disable the paymentMode because it is the only existing one",
    });
  }

  const result = await paymentMode.findOneAndUpdate({ _id: id }, req.body, {
    new: true,
  });

  return res.status(200).json({
    success: true,
    message: "paymentMode updated successfully",
    result,
  });
});

module.exports = {
  findModel,
  createModel,
  deleteModel,
  updateModel,
};
