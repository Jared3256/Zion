const mongoose = require("mongoose");

const netPaymentSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "NetUser",
    required: true,
  },
  vendorId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "NetVendor",
    required: true,
  },
  sessionId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "NetSession",
  },
  paymentMethod: {
    type: String,
    enum: ["CreditCard", "PayPal", "BankTransfer", "Mpesa_AirtelMoney"],
    default: "Mpesa_AirtelMoney",
    required: true,
  },
  paymentStatus: {
    type: String,
    enum: ["initiated", "pending", "completed", "refunded"],
  },
  timestamp: {
    type: Date,
    default: Date.now,
  },
  discountApplied: {
    code: {
      type: String,
    },
    amount: {
      type: Number,
      default: 0,
    },
  },
  refunds: [
    {
      refundId: mongoose.Schema.Types.ObjectId,
      amount: Number,
      reason: String,
      timestamp: {
        type: Date,
        default: Date.now,
      },
    },
  ],
});

const NetPayment = mongoose.model("NetPayment", netPaymentSchema);

module.exports = NetPayment;
