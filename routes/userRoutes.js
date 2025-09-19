import express from "express";
import userAuth from "../middleware/userAuth.js";
import getAuth from "../middleware/getAuth.js";
import { getUserData } from "../controller/userController.js";

const userRouter = express.Router();

userRouter.get("/data", getAuth, getUserData);

export default userRouter;
