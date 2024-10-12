const mongoose = require("mongoose");

const netUserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  macAddresses: {
    type: [String],
    default: [],
  },
  subscriptions: [
    {
      vendorId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "NetVendor",
        required: true,
      },
      plan: {
        type: String,
        enum: ["hourly", "daily", "weekly", "monthly"],
        default: "hourly",
      },
      status: {
        type: String,
        enum: ["active", "inactive", "expired"],
        default: "active",
      },
      validUntil: Date,
    },
  ],
  sessions: [
    {
      sessionId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "NetSession",
      },
      routerId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "NetRouter",
      },
      vendorId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "NetVendor",
      },
      startTime: {
        type: Date,
        default: Date.now,
      },
      endTime: {
        type: Date,
      },
      dataUsed: {
        type: Number,
        default: 0,
      },
    },
  ],
  paymentHistory: [
    {
      paymentId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "NetPayment",
      },
      amount: {
        type: Number,
        default: 0,
      },
      method: {
        type: String,
        enum: ["CreditCard", "PayPal", "BankTransfer", "Mpesa_AirtelMoney"],
        default: "Mpesa_AirtelMoney",
        required: true,
      },
      timestamp: {
        type: Date,
        default: Date.now,
      },
      vendorId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "NetVendor",
      },
    },
  ],
});

const NetUser = mongoose.model("NetUser", netUserSchema);

module.exports = NetUser;
