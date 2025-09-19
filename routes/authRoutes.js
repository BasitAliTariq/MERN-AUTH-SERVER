import express from "express";
import {
  isAuthenticated,
  login,
  logout,
  register,
  resetPassword,
  sendResetOtp,
  sendVerifyOTP,
  verifyEmail,
} from "../controller/authController.js";
import userAuth from "../middleware/userAuth.js";
import getAuth from "../middleware/getAuth.js";

const authRouter = express.Router();

authRouter.post("/register", register);
authRouter.post("/login", login);
authRouter.post("/logout", logout);
// authRouter.post("/send-verify-otp", userAuth, sendVerifyOTP); //userAuth is middleare
// authRouter.post("/send-verify-otp", getAuth, sendVerifyOTP);
// authRouter.post("/verify-account", userAuth, verifyEmail);
// authRouter.get("/is-auth", getAuth, isAuthenticated);
// authRouter.post("/send-reset-otp", sendResetOtp);
// authRouter.post("/reset-password", resetPassword);

authRouter.post("/send-verify-otp", userAuth, sendVerifyOTP);
authRouter.post("/verify-account", userAuth, verifyEmail);
authRouter.get("/is-auth", userAuth, isAuthenticated);
authRouter.post("/send-reset-otp", sendResetOtp);
authRouter.post("/reset-password", resetPassword);
export default authRouter;
