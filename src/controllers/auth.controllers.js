import axios from "axios";
import jwt from "jsonwebtoken";
import jwksClient from "jwks-rsa";
import User from "../models/User.models.js"
import { generateNonce, generateState} from "../utils/auth.utils.js";

// Create a JWKS client to get Google's public key for verifying the ID token
const getJwksClient = () => {
  return jwksClient({
    jwksUri: process.env.GOOGLE_JWKS_URL,  // URL to Google's JWKS endpoint
    cache: true,
    rateLimit: true,
  });
};

// Function to get the signing key using the key ID (kid) from the decoded JWT header
const getSigningKey = async (kid) => {
  const client = getJwksClient();
  return new Promise((resolve, reject) => {
    client.getSigningKey(kid, (err, key) => {
      if (err) {
        console.error("Error getting signing key:", err);
        return reject(err);
      }
      const signingKey = key.getPublicKey();  // Get the public key for verification
      resolve(signingKey);
    });
  });
};

// Function to verify the ID token using the signing key
const verifyGoogleToken = async (token) => {
  try {
    // Decode the JWT token to get the header, which contains the key ID (kid)
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded) {
      throw new Error("Invalid token");
    }

    const kid = decoded.header.kid;  // Extract the key ID (kid)
    const signingKey = await getSigningKey(kid);  // Get the signing key

    // Verify the token using the signing key
    const verifiedToken = jwt.verify(token, signingKey, {
      algorithms: ["RS256"],  // Expected signing algorithm
      audience: process.env.GOOGLE_CLIENT_ID,  // Validate the audience against the Google client ID
    });

    return verifiedToken;  // Return the verified token if valid
  } catch (error) {
    console.log("Error verifying token:", error);
    throw new Error("Token verification failed");
  }
};

// Redirect user to Google Login
const googleLogin = (req, res) => {
  // Generate state and nonce for CSRF protection and replay attack prevention
  const state = generateState();
  const nonce = generateNonce();

  // Store state and nonce in session cookies
  res.cookie("oauth_state", state, {
    httpOnly: true,
    maxAge: 600000,  // 10 minutes
    sameSite: "lax",
  });
  res.cookie("oauth_nonce", nonce, {
    httpOnly: true,
    maxAge: 600000,  // 10 minutes
    sameSite: "lax",
  });

  // Build Google OAuth URL
  const googleAuthUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${process.env.GOOGLE_CLIENT_ID}&redirect_uri=${process.env.GOOGLE_REDIRECT_URI}&response_type=code&scope=email%20profile%20openid&state=${state}&nonce=${nonce}`;

  // Redirect user to Google login page
  res.redirect(googleAuthUrl);
};

// Handle Google Callback and Exchange Code for Tokens
const googleCallback = async (req, res) => {
  try {
    const { code, state } = req.query;
    const savedState = req.cookies.oauth_state;
    const savedNonce = req.cookies.oauth_nonce;

    // Clear the cookies after use
    res.clearCookie("oauth_state");
    res.clearCookie("oauth_nonce");

    // Validate the state parameter to prevent CSRF
    if (!state || !savedState || state !== savedState) {
      return res.status(401).json({ message: "Invalid state parameter" });
    }

    // Exchange authorization code for Google tokens
    const tokenResponse = await axios.post(
      "https://oauth2.googleapis.com/token",
      null,
      {
        params: {
          client_id: process.env.GOOGLE_CLIENT_ID,
          client_secret: process.env.GOOGLE_CLIENT_SECRET,
          redirect_uri: process.env.GOOGLE_REDIRECT_URI,
          code,
          grant_type: "authorization_code",
        },
      }
    );

    const { id_token, access_token, refresh_token } = tokenResponse.data;

    // Check if the id_token exists
    if (!id_token) {
      return res.status(401).json({ message: "Invalid ID token" });
    }

    // Verify the ID token
    const decodedToken = await verifyGoogleToken(id_token);
    if (!decodedToken) {
      return res.status(401).json({ message: "Invalid ID token" });
    }

    // Validate the nonce to prevent replay attacks
    if (!decodedToken.nonce || decodedToken.nonce !== savedNonce) {
      return res.status(401).json({ message: "Invalid nonce parameter" });
    }

    // Check if user exists in database, else create a new user
    let user = await User.findOne({ googleId: decodedToken.sub });
    if (!user) {
      user = await User.create({
        googleId: decodedToken.sub,
        email: decodedToken.email,
        name: decodedToken.name,
        refreshToken: refresh_token || null,
      });
    } else if (refresh_token) {
      // Update refresh token if it has changed
      user.refreshToken = refresh_token;
      await user.save();
    }

    // Generate a JWT token for the user to maintain session
    const accessToken = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    // Set the JWT token in a cookie
    res.cookie("access_token", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 3600000,  // 1 hour
    });

    // Send the user data and message back to the client
    res.json({
      message: "Login successful",
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
      },
    });
  } catch (error) {
    console.error("OAuth Callback Error:", error.message);
    res.status(500).json({ message: "Authentication failed" });
  }
};

// Get the authenticated user's profile
const getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("-refreshToken -__v");

    // Check if user exists
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Send back the user's profile
    res.json({
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
      },
    });
  } catch (error) {
    console.error("Get Profile Error:", error.message);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Logout User and Clear the JWT cookie
const logout = (req, res) => {
  res.clearCookie("access_token");
  res.json({ message: "Logout successful" });
};
const testRoute = async(req,res)=>{
    console.log("test route hit");
    res.status(201).json({
        message:"Test Route hit"
    })

}
export { googleLogin, googleCallback, getProfile, logout,testRoute };
