const removePaymentMode = async (Model, req, res) => {
  return res.status(403).json({
    success: false,
    result: null,
    message: "you can't delete payment mode after it has been created",
  });
};

module.exports = removePaymentMode;
