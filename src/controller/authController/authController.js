const User = require("../../models/app/User");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const asyncHandler = require("express-async-handler");
const { v7: uuid } = require("uuid");
const ResetCode = require("../../models/app/ResetCode");

// @desc Login
// @router POST /auth
// @access Public
const login = asyncHandler(async (req, res) => {
  // Login method
  const { username, password } = req.body;

  if (!username) {
    return res.status(400).json({ message: "Username is required" });
  }
  if (!password) {
    return res.status(400).json({ message: "Password is required" });
  }

  const foundUser = await User.findOne({ username }).exec();

  if (!foundUser) {
    return res.status(401).json(`${username} does not match any user`);
  }

  if (foundUser.status !== "Activated") {
    return res.status(401).json("Unauthorized : Account is deactivated");
  }

  const passwordMatch = await bcrypt.compare(password, foundUser.password);

  if (!passwordMatch) {
    return res.status(401).json("Invalid password provided.");
  }

  // Save the active role in the user instance
  const active_role = foundUser.roles[foundUser.roles.length - 1];
  foundUser.active_role = active_role;

  await foundUser.save();

  // Access Token with 20 seconds to live
  const accessToken = jwt.sign(
    {
      UserInfo: {
        username: foundUser.username,
        roles: foundUser.roles,
        first_name: foundUser.first_name,
        last_name: foundUser.last_name,
        bio: foundUser.bio,
        active: foundUser.active,
        timezone: foundUser.timezone,
        active_role: active_role,
      },
    },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: "30min" }
  );

  // refresh token
  const refreshToken = jwt.sign(
    {
      username: foundUser.username,
      roles: foundUser.roles,
      first_name: foundUser.first_name,
      last_name: foundUser.last_name,
      bio: foundUser.bio,
      active: foundUser.active,
      timezone: foundUser.timezone,
      active_role: foundUser.roles[foundUser.roles.length - 1],
    },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: "12h" }
  );

  // create secure cookie with refresh token
  res.cookie("jwt", refreshToken, {
    http: true,
    secure: true,
    sameSite: "None",
    maxAge: 12 * 60 * 60 * 1000, //12 hour maximum time to live,
  });

  // sendAccessToken({accessToken})
  res.json({ accessToken });
});

// @desc change_role
// @router PUT /auth/change_role
// @access Private
const change_role = asyncHandler(async (req, res) => {
  const { username, role } = req.body;

  if (!role || !username) {
    return res.status(400).json({ message: "Invalid request" });
  }

  const foundUser = await User.findOne({ username });

  if (!foundUser) {
    return res.status(404).json({ message: "No user found" });
  }

  // update the found user role to match
  foundUser.active_role = role;

  // save the user back to the database
  await foundUser.save();

  res.json({ message: "role changed success" });
});

// @desc Refresh
// @router POST /auth/refresh
// @access Public
const refresh = asyncHandler(async (req, res) => {
  const cookies = req.cookies;

  if (!cookies?.jwt) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const refreshToken = cookies.jwt;
  console.log("🚀 ~ refresh ~ refreshToken:", refreshToken);

  jwt.verify(
    refreshToken,
    process.env.REFRESH_TOKEN_SECRET,
    asyncHandler(async (err, decoded) => {
      if (err) return res.status(401).json({ message: "Unauthorised Token" });

      const foundUser = await User.findOne({ username: decoded.username });

      if (!foundUser) {
        return res.status(401).json({ message: "Unauthorized" });
      }

      const accessToken = jwt.sign(
        {
          UserInfo: {
            username: foundUser.username,
            roles: foundUser.roles,
            first_name: foundUser.first_name,
            last_name: foundUser.last_name,
            bio: foundUser.bio,
            active: foundUser.active,
            timezone: foundUser.timezone,
            active_role: foundUser.active_role,
          },
        },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: "30min" }
      );
      res.json({ accessToken });
    })
  );
});

// @desc reset Password
// @Router POST /auth/reset
// @access Public
const ResetCodePass = asyncHandler(async (request, response) => {
  //  get email from the request query
  const { email } = request.query;

  const code = String(uuid()).toUpperCase().slice(24, 36);
  // Find the user with the email provided
  const savedUser = await User.findOne({ username: email });

  if (!savedUser) {
    return response.status(400).json({ message: "Account Not Found" });
  }

  const resetObject = {
    email,
    code,
  };

  // Check if there exists a code already exists for the email
  let savedCode = await ResetCode.findOne({ email });

  if (!savedCode) {
    savedCode = await ResetCode.create(resetObject);
  } else {
    savedCode.code = code;
    await savedCode.save();
  }

  response.json({ message: code });
});

// @desc reset Password
// @Router POST /auth/reset
// @access Public
const ResetPassword = asyncHandler(async (request, response) => {
  //  get code and password from the request query
  const { code, password } = request.query;

  // Check if there exists a code already exists for the email
  let savedCode = await ResetCode.findOne({ code });

  if (!savedCode) {
    return response.status(400).json({ message: "Invalid Code received" });
  }

  const email = savedCode.email;

  // Find user and changed the password
  const savedUser = await User.findOne({ username: email });

  // encrypt the password
  const encryptPass = await bcrypt.hash(password, 16);
  console.log(encryptPass);
  savedUser.password = encryptPass;

  await savedUser.save();

  const id = savedCode._id;

  await ResetCode.findByIdAndDelete(id);

  response.json({ message: `Password Reset Success` });
});

// @desc Logout
// @router POST /auth/logout
// @access Public
const logout = asyncHandler(async (req, res) => {
  console.log("Logout received");
  // Logout method
  const cookies = req.cookies;
  console.log("🚀 ~ logout ~ cookies:", cookies);

  if (!cookies?.jwt) {
    console.log("🚀 ~ logout ~ cookies?.jwt:", cookies?.jwt);
    return res.status(204).json({ message: "No token received", cookies });
  }

  res.clearCookie("jwt", { httpOnly: true, sameSite: "None" });

  res.json({ message: "Logout successful" });
});

module.exports = {
  change_role,
  login,
  refresh,
  logout,
  ResetCodePass,
  ResetPassword,
};
