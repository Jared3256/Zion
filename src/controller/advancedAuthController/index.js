const asyncHandler = require("express-async-handler");
const User = require("../../models/app/user.model");
const bcrypt = require("bcrypt");
const {
  generateVerificationToken,
  generateTokenAndSetCookie,
  generateResetToken,
} = require("../../utils/system.utils");
const {
  sendVerificationEmail,
  sendWelcomeEmail,
  sendPasswordResetEmail,
  sendResetSuccessEmail,
} = require("../../utils/mailtrap/email");

const signup = asyncHandler(async (req, res) => {
  const { email, password, name } = req.body;

  try {
    if (!email || !password || !name) {
      return res.status(400).json({ message: "All field are required" });
    }

    //   Check if the email is already taken
    const userFound = await User.findOne({ email });

    if (userFound) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 16);
    const verificationToken = generateVerificationToken();
    const user = new User({
      email,
      password: hashedPassword,
      name,
      verificationToken,
      verificationTokenExpiresAt: Date.now() + 24 * 60 * 60 * 1000,
    });

    await user.save();

    //   Generate and set Token cookies
    generateTokenAndSetCookie(res, user._id);

    //   send verification email
    await sendVerificationEmail(user.email, verificationToken);

    res.status(201).json({
      success: true,
      message: "User created successfully",
      user: {
        ...user._doc,
        password: null,
      },
    });
  } catch (error) {
    console.log(error);
  }
});

const verifyemail = asyncHandler(async (req, res) => {
  const { code } = req.body;

  try {
    const userWithCode = await User.findOne({
      verificationToken: code,
      verificationTokenExpiresAt: { $gt: Date.now() },
    });

    if (!userWithCode) {
      return res
        .status(400)
        .json({ message: "Invalid or expired verification Token" });
    }

    userWithCode.isVerified = true;
    userWithCode.verificationToken = undefined;
    userWithCode.verificationTokenExpiresAt = undefined;

    await userWithCode.save();

    // send welcome email to the user
    await sendWelcomeEmail(userWithCode.email, userWithCode.name);
  } catch (error) {
    console.log(error);
  }
});

const login = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check is password and email are provided
    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Credentials are required for authentication" });
    }

    // find user with the provided email
    const foundUser = await User.findOne({ email });

    if (!foundUser) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const isPasswordValid = await bcrypt.compare(password, foundUser.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid password provided" });
    }

    // generate token and set cookie
    generateTokenAndSetCookie(res, foundUser._id);

    // Update user last login
    foundUser.lastLogin = new Date();

    await foundUser.save();

    return res.status(200).json({
      message: "Login success",
      user: {
        ...foundUser._doc,
        password: undefined,
      },
    });
  } catch (error) {
    console.log(error);
  }
});

const logout = asyncHandler(async (req, res) => {
  res.clearCookie("jwt");
  res.status(200).json({ success: true, message: "logged out successfully" });
});

const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    // Generate reset token
    const resetToken = generateResetToken();
    const resetTokenExpiry = Date.now() + 1 * 60 * 60 * 1000; // 1 hour

    user.resetPasswordToken = resetToken;
    user.resetPasswordExpiresAt = resetTokenExpiry;

    await user.save();

    // send email
    const link = `http://localhost:5173/api/auth/reset_password/${resetToken}`;
    console.log(link);
    await sendPasswordResetEmail(email, link);
  } catch (error) {
    console.error(error);
  }
});

const resetpassword = asyncHandler(async (req, res) => {
  const { token } = req.params;

  const { password } = req.body;

  const user = await User.findOne({
    resetPasswordToken: token,
    resetPasswordExpiresAt: { $gt: Date.now() },
  });

  if (!user) {
    return res.status(400).json({ message: "Invalid Token passed" });
  }

  // update the password
  const hashedPassword = await bcrypt.hash(password, 16);

  user.password = hashedPassword;
  user.resetPasswordExpiresAt = undefined;
  user.resetPasswordToken = undefined;

  await user.save();

  // send Password reset email success

  await sendResetSuccessEmail(user.email);

  return res.status(200).json({ message: "Password reset successful" });
});

module.exports = {
  signup,
  login,
  logout,
  verifyemail,
  forgotPassword,
  resetpassword,
};
