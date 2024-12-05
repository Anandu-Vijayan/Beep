import jwt from "jsonwebtoken";
import User from "../models/user.model.js";

export const protectRoute = async (req, res, next) => {
  try {
    const token = req.cookies.jwt;
    if (!token) {
      return res.status(401).json({ msg: "Not authorized, token is required" });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded) {
      return res.status(401).json({ msg: "Not authorized, token is expired" });
    }
    const user = await User.findById(decoded.userId).select("-password");
    if (!user) {
      return res
        .status(401)
        .json({ msg: "Not authorized, user no longer exists" });
    }
    req.user = user;
    next();
  } catch (error) {
    console.log("Error in protectRoute middleeware",error.message);
    return res.status(401).json({ msg: "Not authorized, token is invalid" });
  }
};
