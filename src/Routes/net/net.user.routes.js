const express = require("express");
const {
  createUser,
  netLogin,
  netUpdateUser,
} = require("../../controller/net/netUserController");

// Import the netUserController

const router = express.Router();

// create user Endpoint
// Method POST
router.route("/auth/create").post(createUser);

// Login User Endpoint
// Method POST
router.route("/auth/login").post(netLogin);

// Update user details Endpoint
// Method PUT
router.route("/api/update").put(netUpdateUser);
module.exports = router;
