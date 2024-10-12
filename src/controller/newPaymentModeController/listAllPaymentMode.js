const listAllPaymentMode = async (Model, req, res) => {
  const models = await Model.find();

  if (!models?.length) {
    return res.status(404).json({ message: "" });
  }
  res.json(models);
};
module.exports = listAllPaymentMode;
