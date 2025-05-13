
import express from "express";
import { getProfile, googleCallback, googleLogin, logout, testRoute } from "../controllers/auth.controllers.js";

// app.use("/api/v1/user", router);


const router = express.Router();

router.get("/test",testRoute)
router.get("/auth/google",googleLogin);
router.get("/auth/google/callback",googleCallback);
router.get("/profile",getProfile);
router.get("/logout",logout);

export default  router;