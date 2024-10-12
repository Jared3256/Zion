const NetUser = require("../../models/net/user.net");
const asyncHandler = require("express-async-handler");
const bcrypt = require("bcrypt");

// Function to create new Clients
// Access Public
// Endpoint /net/auth/create
const netCreateUser = asyncHandler(async (req, res) => {
  // Get Username, password and email from the req
  // Check if neither is blank
  const { username, password, email } = req.body;

  if (!username || !password || !email) {
    return res.status(400).json({ message: "Missing key information" });
  }

  // Check if the user is already registered
  const foundUser = await NetUser.findOne({ email });

  if (foundUser) {
    return res.status(409).json({ message: `${email} is already registered` });
  }

  // hash the password before storing
  const hashedPassword = await bcrypt.hash(password, 16);

  // create and store the user to the database
  const newUser = new NetUser({
    email,
    username,
    password: hashedPassword,
  });

  await newUser.save();

  res.status(201).json({
    success: true,
    message: "User created successfully",
    user: {
      ...newUser._doc,
      password: undefined,
    },
  });
});

// Function to login Clients
// Access Public
// Endpoint /net/auth/login
const netLogin = asyncHandler(async (req, res) => {
  res.send("Net Login Function");
});

// Function to update user details
// Access Restricted (private)
// Endpoint /net/api/update
const netUpdateUser = asyncHandler(async (req, res) => {
  res.send("Net update User Function");
});

module.exports = {
  createUser: netCreateUser,
  netLogin,
  netUpdateUser,
};
