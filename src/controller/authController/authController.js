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
        active_role: foundUser.roles[foundUser.roles.length - 1],
      },
    },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: "1h" }
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
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  // sendAccessToken({accessToken})
  res.json({ accessToken });
});

// @desc Refresh
// @router POST /auth/refresh
// @access Public
const refresh = asyncHandler(async (req, res) => {
  // Refresh method
  const { changed_role } = req.query;

  const cookies = req.cookies;

  if (!cookies?.jwt) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const refreshToken = cookies.jwt;

  jwt.verify(
    refreshToken,
    process.env.REFRESH_TOKEN_SECRET,
    asyncHandler(async (err, decoded) => {
      if (err) return res.status(401).json({ message: "Forbidden" });

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
            active_role:
              changed_role || foundUser.roles[foundUser.roles.length - 1],
          },
        },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: "1h" }
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

  // necrypt the password
  const encryptPass = await bcrypt.hash(password, 16);
  console.log(encryptPass);
  savedUser.password = encryptPass;

  await savedUser.save();

  const id = savedCode._id;

  await ResetCode.findByIdAndDelete(id);

  response.json({ message: `Password Reset Sucess` });
});

// @desc Logout
// @router POST /auth/logout
// @access Public
const logout = asyncHandler(async (req, res) => {
  // Logout method
  const cookies = req.cookies;
  console.log(req.cookies);

  if (!cookies?.jwt) {
    return res.status(204);
  }

  res.clearCookie("token", {
    maxAge: null,
    sameSite: "none",
    httpOnly: true,
    secure: true,
    domain: req.hostname,
    Path: "/",
  });
  res.clearCookie(
    "jwt",
    res.clearCookie("token", {
      maxAge: null,
      sameSite: "none",
      httpOnly: true,
      secure: true,
      domain: req.hostname,
      Path: "/",
    })
  );

  console.log("Response", res.cookies);
  res.json({ message: "Logout successful" });
});

module.exports = {
  login,
  refresh,
  logout,
  ResetCodePass,
  ResetPassword,
};
