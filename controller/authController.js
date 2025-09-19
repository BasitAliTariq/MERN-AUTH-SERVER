// import bcrypt from "bcryptjs";
// import jwt from "jsonwebtoken";
// import userModel from "../models/userModel.js";
// import transporter from "../config/nodemailer.js";
// import {
//   EMAIL_VERIFY_TEMPLATE,
//   PASSWORD_RESET_TEMPLATE,
// } from "../config/emailtemplate.js";
// // sign in

// export const register = async (req, res) => {
//   const { name, email, password } = req.body;
//   if (!name || !email || !password) {
//     return res.json({ success: false, message: "Missing Details" });
//   }

//   try {
//     //handle user already exist
//     const existingUser = await userModel.findOne({ email });
//     if (existingUser) {
//       return res.json({
//         success: false,
//         message: "User already exists",
//       });
//     }
//     //encrypt the pasword
//     const hashedPassword = await bcrypt.hash(password, 10);

//     //create user

//     const user = new userModel({ name, email, password: hashedPassword });
//     await user.save();

//     //create token
//     const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
//       expiresIn: "7d",
//     });

//     //sent above token to user in te form of cookie
//     res.cookie("token", token, {
//       httpOnly: true,
//       secure: process.env.NODE_ENV === "production",
//       sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
//       maxAge: 7 * 24 * 60 * 60 * 1000, //converting 7 days into milliseconds
//     });

//     // Sending welcome email to user

//     const mailOptions = {
//       from: process.env.SENDER_EMAIL,
//       to: email,
//       subject: "Welcome to Auth App",
//       text: `Welcome to  my authentication website.Your account has been created with email id :${email}`,
//     };

//     await transporter.sendMail(mailOptions);

//     return res.json({ success: true });
//   } catch (error) {
//     return res.json({ success: false, message: error.message });
//   }
// };

// export const login = async (req, res) => {
//   const { email, password } = req.body;

//   // Handle if user is not provide email and password
//   if (!email || !password) {
//     return res.json({
//       success: false,
//       message: "Email and password are required",
//     });
//   }

//   try {
//     // find user's email in database
//     const user = await userModel.findOne({ email });

//     // Handle if email is not exist

//     if (!user) {
//       return res.json({
//         success: false,
//         message: "Invalid email",
//       });
//     }

//     // Compere the user's password with the pasword stored in db

//     const isMatch = await bcrypt.compare(password, user.password);
//     if (!isMatch) {
//       return res.json({
//         success: false,
//         message: "Invalid password",
//       });
//     }
//     //create token
//     const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
//       expiresIn: "7d",
//     });

//     //sent above token to user in te form of cookie
//     res.cookie("token", token, {
//       httpOnly: true,
//       secure: process.env.NODE_ENV === "production",
//       sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
//       maxAge: 7 * 24 * 60 * 60 * 1000, //converting 7 days into milliseconds
//     });
//     return res.json({ success: true });
//   } catch (error) {
//     return res.json({ success: false, message: error.message });
//   }
// };

// export const logout = async (req, res) => {
//   try {
//     // clear cookie
//     res.clearCookie("token", {
//       httpOnly: true,
//       secure: process.env.NODE_ENV === "production",
//       sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
//     });
//     return res.json({ success: true, message: "Logged Out" });
//   } catch (error) {
//     return res.json({ success: false, message: error.message });
//   }
// };

// // Send verification OTP email to the User's mail

// export const sendVerifyOTP = async (req, res) => {
//   try {
//     const { userId } = req.body; //user Id comes from middleware/userAuth.js where token is decoded and get id

//     const user = await userModel.findById(userId);
//     if (!user) {
//       return res.json({ success: false, message: "User not found" });
//     }
//     // check that user is already verified or not
//     if (user.isAccountVerified) {
//       return res.json({ success: false, message: "Account Already verified" });
//     }

//     //generting 6 digit OTP

//     const otp = String(Math.floor(100000 + Math.random() * 900000));

//     // Store this otp in data base
//     user.verifyOtp = otp;
//     //opt expire after one day/24 hour
//     user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000;
//     await user.save();

//     // Send otp to user through email
//     const mailOptions = {
//       from: process.env.SENDER_EMAIL,
//       to: user.email,
//       subject: "Account verification OTP",
//       //text: `Your OTP is ${otp}. Verify your account using this OTP`,
//       html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}", otp).replace(
//         "{{email}}",
//         user.email
//       ),
//     };

//     await transporter.sendMail(mailOptions);

//     res.json({ success: true, message: "Verification OTP sent to Email" });
//   } catch (error) {
//     return res.json({ success: false, message: error.message });
//   }
// };

// //verify email using OTP

// export const verifyEmail = async (req, res) => {
//   const { userId, otp } = req.body; //user Id comes from middleware/userAuth.js where token is decoded and get id

//   if (!userId || !otp) {
//     return res.json({ success: false, message: "Missing Details" });
//   }

//   try {
//     //find user from database by Id
//     const user = await userModel.findById(userId);
//     if (!user) {
//       return res.json({ success: false, message: "User not found" });
//     }
//     //handle condition if user donot enter  otp or enter wrong otp
//     if (user.verifyOtp === "" || user.verifyOtp !== otp) {
//       return res.json({ success: false, message: "Invalid OTP" });
//     }

//     //handle  condition if user enter otp afetr expiry date
//     if (user.verifyOtpExpireAt < Date.now()) {
//       return res.json({ success: false, message: "OTP Expired" });
//     }

//     //some changing in db
//     user.isAccountVerified = true;
//     user.verifyOtp = "";
//     user.verifyOtpExpireAt = 0;

//     await user.save();
//     return res.json({ success: true, message: "Email Verified Successfully" });
//   } catch (error) {
//     return res.json({ success: false, message: error.message });
//   }
// };

// // check if user is authenticated/logged in or not

// export const isAuthenticated = (req, res) => {
//   try {
//     return res.json({ success: true });
//   } catch (error) {
//     return res.json({ success: false, message: error.message });
//   }
// };

// // send password reset otp

// export const sendResetOtp = async (req, res) => {
//   const { email } = req.body;

//   // handle condition if user does not provide email

//   if (!email) {
//     return res.json({ success: false, message: "Email is required" });
//   }

//   try {
//     const user = await userModel.findOne({ email });

//     if (!user) {
//       return res.json({ success: false, message: "User not found" });
//     }
//     //generting 6 digit OTP

//     const otp = String(Math.floor(100000 + Math.random() * 900000));

//     // Store this otp in data base
//     user.resetOtp = otp;
//     //opt expire after one 15 minutes
//     user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000;
//     await user.save();

//     // Send otp to user through email
//     const mailOptions = {
//       from: process.env.SENDER_EMAIL,
//       to: user.email,
//       subject: "Password Reset OTP",
//       //text: `Your OTP for resetting your password is ${otp}.Use this OTP to proceed with resetting your password`,
//       html: PASSWORD_RESET_TEMPLATE.replace("{{otp}}", otp).replace(
//         "{{email}}",
//         user.email
//       ),
//     };

//     await transporter.sendMail(mailOptions);

//     return res.json({
//       success: true,
//       message: "OTP sent to your Email",
//     });
//   } catch {
//     return res.json({ success: false, message: error.message });
//   }
// };

// // reset user password

// export const resetPassword = async (req, res) => {
//   const { email, otp, newPassword } = req.body;

//   if (!email || !otp || !newPassword) {
//     return res.json({
//       success: false,
//       message: "Email OTP and new password  are required",
//     });
//   }

//   try {
//     const user = await userModel.findOne({ email });

//     // handle condition if user is not found with provide mail
//     if (!user) {
//       return res.json({ success: false, message: "User not found" });
//     }

//     // handle condition if user enter invalid otp

//     if (user.resetOtp === "" || user.resetOtp !== otp) {
//       return res.json({ success: false, message: "Invalid OTP" });
//     }

//     //Now check the expiry of otp

//     if (user.resetOtpExpireAt < Date.now()) {
//       return res.json({ success: false, message: "OTP Expired" });
//     }
//     // encrypt the new pasword
//     const hashedPassword = await bcrypt.hash(newPassword, 10);
//     // update the password
//     user.password = hashedPassword;

//     user.resetOtp = "";
//     user.resetOtpExpireAt = 0;
//     user.save();
//     return res.json({
//       success: true,
//       message: "Password has been reset sucessfully",
//     });
//   } catch (error) {
//     return res.json({ success: false, message: error.message });
//   }
// };

//Production

// Production

import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import UserModel from "../models/userModel.js";
import transporter from "../config/nodemailer.js";
// import {
//   EMAIL_VERIFY_TEMPLATE,
//   PASSWORD_RESET_TEMPLATE,
// } from "../config/emailTemplates.js";

import {
  EMAIL_VERIFY_TEMPLATE,
  PASSWORD_RESET_TEMPLATE,
} from "../config/emailtemplate.js";

export async function register(req, res) {
  const { email, password, name } = req.body;
  if (!email || !name || !password)
    return res.json({ success: false, message: "Missing Details" });
  try {
    const existingUser = await UserModel.findOne({ email });
    if (existingUser)
      return res.json({ success: false, message: "User already exists" });
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new UserModel({ name, email, password: hashedPassword });
    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });
    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    const emailOptions = {
      from: process.env.SENDER_EMAIL,
      to: email,
      subject: "Welcome to Hassaan's Website",
      text: `Welcome to our website. Your account has been created with email id : ${email}`,
    };
    await transporter.sendMail(emailOptions);

    return res.json({ success: true });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
}

export async function login(req, res) {
  const { email, password } = req.body;
  if (!email || !password)
    return res.json({
      success: false,
      message: "Email and Password are required!",
    });
  try {
    const user = await UserModel.findOne({ email });
    if (!user) return res.json({ success: false, message: "Invalid Email!" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.json({ success: false, message: "Invalid Password!" });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });
    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.json({ success: true, message: "Logged In Successfully!" });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
}

export async function logout(req, res) {
  try {
    res.clearCookie("token", {
      httpOnly: true,
      secure: true,
      sameSite: "none",
    });
    return res.json({ success: true, message: "Logged Out" });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
}

export async function sendVerifyOtp(req, res) {
  try {
    const { userId } = req.body;
    const user = await UserModel.findById(userId);
    if (user.isAccountVerified)
      return res.json({ success: true, message: "Email already Verified" });

    const OTP = String(Math.floor(100000 + Math.random() * 900000));
    user.verifyotp = OTP;
    user.verifyotpExpireAt = Date.now() + 24 * 60 * 60 * 1000;

    await user.save();

    const emailOptions = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Email Verification OTP",
      html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}", OTP).replace(
        "{{email}}",
        user.email
      ),
    };
    await transporter.sendMail(emailOptions);

    return res.json({
      success: true,
      message: "Verification OTP sent on email!",
    });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
}
export async function verifyEmail(req, res) {
  const { userId } = req.body;
  const OTP = req.headers["x-otp"];

  if (!userId || !OTP)
    return res.json({ success: false, message: "Missing Details." });
  try {
    const user = await UserModel.findById(userId);
    if (!user) return res.json({ success: false, message: "User not found" });
    if (user.verifyotp === "" || user.verifyotp !== OTP)
      return res.json({ success: false, message: "Invalid OTP" });
    if (user.verifyotpExpireAt < Date.now())
      return res.json({ success: false, message: "OTP expired!" });

    user.isAccountVerified = true;
    user.verifyotp = "";
    user.verifyotpExpireAt = 0;
    await user.save();
    return res.json({
      success: true,
      message: "Email Verified Successfully!",
    });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
}

export async function isAuthenticated(req, res) {
  try {
    return res.json({ success: true });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
}

export async function sendResetOtp(req, res) {
  const { email } = req.body;
  if (!email)
    return res.json({ success: false, message: "Email is required!" });
  try {
    const user = await UserModel.findOne({ email });
    if (!user) return res.json({ success: false, message: "User not found" });

    const OTP = String(Math.floor(100000 + Math.random() * 900000));
    user.resetotp = OTP;
    user.resetotpExpireAt = Date.now() + 15 * 60 * 1000;

    await user.save();

    const emailOptions = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Password Reset OTP",
      html: PASSWORD_RESET_TEMPLATE.replace("{{otp}}", OTP).replace(
        "{{email}}",
        user.email
      ),
    };
    await transporter.sendMail(emailOptions);

    return res.json({
      success: true,
      message: "OTP sent to your email!",
    });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
}
export async function resetPassword(req, res) {
  const { email, OTP, newPassword } = req.body;
  if (!email || !OTP || !newPassword)
    return res.json({
      success: false,
      message: "OTP, Email and New Password is required!",
    });
  try {
    const user = await UserModel.findOne({ email });
    if (!user) return res.json({ success: false, message: "User not found" });
    if (user.resetotp === "" || user.resetotp !== OTP)
      return res.json({ succes: false, message: "Invalid OTP" });
    if (user.resetotpExpireAt < Date.now())
      return res.json({ succes: false, message: "OTP expired!" });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetotp = "";
    user.resetotpExpireAt = 0;

    await user.save();
    return res.json({
      success: true,
      message: "Password has been reset successfully!",
    });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
}
