import express from "express";
import {
  registerUser,
  loginUser,
  updateUser,
  deleteUser,
  userAnalytics,
  getAllUsers,
} from "../controllers/user.controller";
import { authorizeRoles, isAuthenticated } from "../utils/auth";

const userRouter = express.Router();

userRouter.post("/register", registerUser);

userRouter.post("/login", loginUser);

userRouter.put("/update", isAuthenticated, updateUser);

userRouter.delete(
  "/delete",
  authorizeRoles("admin"),
  isAuthenticated,
  deleteUser
);

userRouter.get(
  "/analytics",
  isAuthenticated,
  authorizeRoles("admin"),
  userAnalytics
);

userRouter.get(
  "/all",
  isAuthenticated,
  authorizeRoles("admin"),
  getAllUsers
);

export default userRouter;
