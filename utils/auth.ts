import { Request, Response, NextFunction } from "express";
import { CatchAsyncError } from "../middlewares/catchAsyncError";
import ErrorHandler from "./ErrorHandler";
import jwt, { JwtPayload } from "jsonwebtoken";
import userModel from "../models/user.model";

import "dotenv/config";

import { iuser } from "../controllers/user.controller";

//using interface for req.user
declare module "express" {
  interface Request {
    user?: iuser;
  }
}

//Authenticate user
export const isAuthenticated = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Access the authorization header to validate the request
      const authHeader = req.headers.authorization;

      if (!authHeader) {
        return res.status(401).json({ error: "Authentication Failed" });
      }

      // Extract the token from the authorization header
      const token = authHeader.split(" ")[1];

      //Verify token
      const decoded = jwt.verify(
        token,
        process.env.JWT_ACCESS_TOKEN as string
      ) as JwtPayload;

      if (!decoded) {
        return next(new ErrorHandler("Access token not valid", 400));
      }

      // Extract the userId from the decoded token
      const userId = decoded.userId;
      const role = decoded.role;

      if (!userId) {
        return next(new ErrorHandler("User ID not found in token", 400));
      }

      // Set the userId in the request object for use in controllers
      req.user = { userId, role } as any;

      next();
    } catch (error: any) {
      return next(new ErrorHandler(error.message, 400));
    }
  }
);

//validate user role
export const authorizeRoles = (...roles: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    // Get the user role as a string
    const userRole = req.user?.role || "";
    
    if (!roles.includes(userRole)) {
      return next(
        new ErrorHandler(
          `Role: ${userRole} is not allowed to access this resource`,
          403
        )
      );
    }
    next();
  };
};
