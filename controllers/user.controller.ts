import { Request, Response, NextFunction } from "express";
import userModel, { IUser } from "../models/user.model";
import ErrorHandler from "../utils/ErrorHandler";
import { CatchAsyncError } from "../middlewares/catchAsyncError";
import jwt, { Secret, JwtPayload } from "jsonwebtoken";

import ejs from "ejs";
import path from "path";
import sendMail from "../utils/sendEmail";

//using interface for req.user

export interface iuser {
  userId: string;
  role: string;
}
declare module "express" {
  interface Request {
    user?: iuser;
  }
}

//Register user interface
interface IRegistrationBody {
  name: string;
  email: string;
  password: string;
  role: string;
}

//Register user
export const registerUser = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { name, email, password, role } = req.body;

      //Check if email already exists
      const isEmailExist = await userModel.findOne({ email });
      if (isEmailExist) {
        return next(new ErrorHandler("Email already exists", 400));
      }

      const user: IRegistrationBody = {
        name,
        email,
        password,
        role,
      };

      const data = {
        user: { name: user.name, password: user.password, role: user.role },
      };
      await ejs.renderFile(
        path.join(__dirname, "../mails/activation-mail.ejs"),
        data
      );

      //send email to user
      try {
        //store user data in database
        await userModel.create({
          name,
          email,
          password,
          role,
        });

        //send email
        await sendMail({
          email: user.email,
          subject: "Account Creation",
          template: "activation-mail.ejs",
          data,
        });

        res.status(201).json({
          message: `User account created successfully`,
        });
      } catch (error: any) {
        console.log(error);
        return next(new ErrorHandler(error.message, 400));
      }
    } catch (error: any) {
      console.log(error);
      return next(new ErrorHandler(error.message, 400));
    }
  }
);

//Login user
interface ILoginRequest {
  email: string;
  password: string;
}

export const loginUser = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { email, password } = req.body as ILoginRequest;
      if (!email || !password) {
        res.status(400).json({
          message: "Invalid credentials",
        });
      }

      const user = await userModel.findOne({ email }).select("+password");

      if (!user) {
        return next(new ErrorHandler("Invalid email or password", 403));
      }

      //check password
      const isPasswordMatch = await user.comparePassword(password);
      if (!isPasswordMatch) {
        return next(new ErrorHandler("Invalid email or password", 403));
      }

      // Create a Access token
      const accesstoken = jwt.sign(
        {
          userId: user._id,
          role: user.role,
        },
        process.env.JWT_ACCESS_TOKEN as Secret,
        { expiresIn: "72h" }
      );

      return res.status(200).send({
        name: user.name,
        role: user.role,
        accesstoken,
      });
    } catch (error: any) {
      return next(new ErrorHandler(error.message, 403));
    }
  }
);

//Update user
export const updateUser = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { name, password, role } = req.body;
      const userId = req.user?.userId;

      const user = await userModel.findById(userId);

      if (!user) {
        return next(new ErrorHandler("User not found", 404));
      }

      // Create an object to store fields to update
      const updateFields: { [key: string]: any } = {};

      // Conditionally add fields to update
      if (name) updateFields.name = name;
      if (role) {
        updateFields.role = role;
      }

      // Handle password separately as it needs to be hashed
      if (password) {
        // The password will be automatically hashed by the pre-save hook
        user.password = password;
        await user.save();
      }

      // Update other fields if there are any
      if (Object.keys(updateFields).length > 0) {
        await userModel.findByIdAndUpdate(userId, updateFields, {
          new: true,
          runValidators: true,
        });
      }

      res.status(200).json({
        message: "User updated successfully",
      });
    } catch (error: any) {
      return next(new ErrorHandler(error.message, 400));
    }
  }
);

//delete user
export const deleteUser = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user?.userId;

      const user = await userModel.findById(userId);

      if (!user) {
        return next(new ErrorHandler("User not found", 404));
      }

      // Delete the user
      await userModel.findByIdAndDelete(userId);

      res.status(200).json({
        message: "User deleted successfully",
      });
    } catch (error: any) {
      return next(new ErrorHandler(error.message, 400));
    }
  }
);

//analytics
export const userAnalytics = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Get total number of users
      const totalUsers = await userModel.countDocuments();

      // Get count of users by role
      const adminUsers = await userModel.countDocuments({ role: "admin" });
      const salesUsers = await userModel.countDocuments({ role: "sales" });
      const inventoryUsers = await userModel.countDocuments({
        role: "inventory",
      });

      res.status(200).json({
        stats: {
          totalUsers,
          admin: adminUsers,
          sales: salesUsers,
          inventory: inventoryUsers,
        },
      });
    } catch (error: any) {
      return next(new ErrorHandler(error.message, 400));
    }
  }
);

//get all users
export const getAllUsers = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Get all users with only name, email, and role fields
      const users = await userModel.find({}, "name email role");

      res.status(200).json({
        users,
      });
    } catch (error: any) {
      return next(new ErrorHandler(error.message, 400));
    }
  }
);
