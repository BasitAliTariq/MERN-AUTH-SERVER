// import mongoose from "mongoose";

// const userSchema = new mongoose.Schema({
//   name: { type: String, required: true },
//   email: { type: String, required: true, unique: true },
//   password: { type: String, required: true },
//   verifyOtp: { type: String, default: "" },
//   verifyOtpExpireAt: { type: Number, default: 0 },
//   isAccountVerified: { type: Boolean, default: false },
//   resetOtp: { type: String, default: "" },
//   resetOtpExpireAt: { type: Number, default: 0 },
// });

// const userModel = mongoose.models.user || mongoose.model("user", userSchema);

// export default userModel;

import mongoose from "mongoose";

const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  verifyotp: { type: String, default: "" },
  verifyotpExpireAt: { type: Number, default: 0 },
  isAccountVerified: { type: Boolean, default: false },
  resetotp: { type: String, default: "" },
  resetotpExpireAt: { type: Number, default: 0 },
});
const UserModel = mongoose.model.user || mongoose.model("user", UserSchema);

export default UserModel;
