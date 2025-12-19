const express = require("express");
const app = express();
const http = require("http");
const server = http.createServer(app);
const io = require("socket.io")(server);
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const crypto = require("crypto");

// Environment variables
const MONGO_URI = process.env.MONGO_URI;
const SALT = process.env.SALT || crypto.randomBytes(32).toString("hex");
const SALT_ROUNDS = 24;

// Encryption helpers using AES-256-GCM
const ENCRYPTION_KEY = crypto.scryptSync(SALT, "secure-chat-salt", 32);

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-gcm", ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  const authTag = cipher.getAuthTag();
  return iv.toString("hex") + ":" + authTag.toString("hex") + ":" + encrypted;
}

function decrypt(encryptedData) {
  try {
    const parts = encryptedData.split(":");
    const iv = Buffer.from(parts[0], "hex");
    const authTag = Buffer.from(parts[1], "hex");
    const encrypted = parts[2];
    const decipher = crypto.createDecipheriv("aes-256-gcm", ENCRYPTION_KEY, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  } catch (error) {
    return null;
  }
}

// MongoDB connection
mongoose.connect(MONGO_URI)
  .then(() => console.log("🔒 Connected to MongoDB securely"))
  .catch(err => {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  });

// User Schema with encrypted username storage
const userSchema = new mongoose.Schema({
  usernameHash: { type: String, required: true, unique: true },
  usernameEncrypted: { type: String, required: true },
  passwordHash: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date }
});

const User = mongoose.model("User", userSchema);

// Room Schema
const roomSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  passwordHash: { type: String, default: "" },
  creatorHash: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const Room = mongoose.model("Room", roomSchema);

// Session management (in-memory for active sessions only)
const activeSessions = new Map();

// Generate secure session token
function generateSessionToken() {
  return crypto.randomBytes(64).toString("hex");
}

// Hash username for lookup (deterministic)
function hashUsername(username) {
  return crypto.createHmac("sha256", SALT).update(username.toLowerCase()).digest("hex");
}

// Rate limiting
const rateLimits = new Map();
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const MAX_ATTEMPTS = 5;

function checkRateLimit(identifier, action) {
  const key = `${identifier}:${action}`;
  const now = Date.now();
  const record = rateLimits.get(key) || { attempts: 0, windowStart: now };
  
  if (now - record.windowStart > RATE_LIMIT_WINDOW) {
    record.attempts = 0;
    record.windowStart = now;
  }
  
  record.attempts++;
  rateLimits.set(key, record);
  
  return record.attempts <= MAX_ATTEMPTS;
}

// Clean up old rate limit records periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, record] of rateLimits) {
    if (now - record.windowStart > RATE_LIMIT_WINDOW * 2) {
      rateLimits.delete(key);
    }
  }
}, 300000);

app.use(express.static(__dirname + "/public"));
app.use(express.static(__dirname));

io.on("connection", (socket) => {
  console.log("User connected:", socket.id);
  let currentSession = null;
  
  // Secure LOGIN
  socket.on("login", async (data) => {
    try {
      const { username, password } = data;
      
      // Rate limiting
      if (!checkRateLimit(socket.handshake.address, "login")) {
        socket.emit("login-result", {
          success: false,
          message: "⚠️ Too many login attempts. Please wait a minute before trying again.",
          type: "error"
        });
        return;
      }
      
      // Validate input
      if (!username || !password) {
        socket.emit("login-result", {
          success: false,
          message: "🔓 Username and password are required.",
          type: "error"
        });
        return;
      }
      
      if (username.length < 3 || username.length > 30) {
        socket.emit("login-result", {
          success: false,
          message: "Username must be between 3 and 30 characters.",
          type: "error"
        });
        return;
      }
      
      const usernameHash = hashUsername(username);
      const user = await User.findOne({ usernameHash });
      
      if (!user) {
        // Generic error to prevent username enumeration
        socket.emit("login-result", {
          success: false,
          message: "🔓 Invalid credentials.",
          type: "error"
        });
        return;
      }
      
      const passwordValid = await bcrypt.compare(password + SALT, user.passwordHash);
      
      if (!passwordValid) {
        socket.emit("login-result", {
          success: false,
          message: "🔓 Invalid credentials.",
          type: "error"
        });
        return;
      }
      
      // Update last login
      user.lastLogin = new Date();
      await user.save();
      
      // Create session
      const sessionToken = generateSessionToken();
      const decryptedUsername = decrypt(user.usernameEncrypted);
      
      currentSession = {
        token: sessionToken,
        usernameHash: usernameHash,
        username: decryptedUsername
      };
      
      activeSessions.set(sessionToken, currentSession);
      
      socket.emit("login-result", {
        success: true,
        user: { username: decryptedUsername },
        sessionToken: sessionToken,
        message: "🔓 Welcome to Insecure Chat!"
      });
      
      console.log(`[LOGIN] User logged in: ${usernameHash.substring(0, 8)}...`);
    } catch (error) {
      console.error("Login error:", error);
      socket.emit("login-result", {
        success: false,
        message: "An error occurred. Please try again.",
        type: "error"
      });
    }
  });
  
  // Secure SIGNUP
  socket.on("signup", async (data) => {
    try {
      const { username, password } = data;
      
      // Rate limiting
      if (!checkRateLimit(socket.handshake.address, "signup")) {
        socket.emit("signup-result", {
          success: false,
          message: "⚠️ Too many signup attempts. Please wait a minute.",
          type: "error"
        });
        return;
      }
      
      // Validate username
      if (!username || username.length < 3 || username.length > 30) {
        socket.emit("signup-result", {
          success: false,
          message: "Username must be between 3 and 30 characters.",
          type: "error"
        });
        return;
      }
      
      if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
        socket.emit("signup-result", {
          success: false,
          message: "Username can only contain letters, numbers, underscores, and hyphens.",
          type: "error"
        });
        return;
      }
      
      // Validate password
      if (!password || password.length < 8) {
        socket.emit("signup-result", {
          success: false,
          message: "🔓 Password must be at least 8 characters.",
          type: "error"
        });
        return;
      }
      
      if (password.length > 128) {
        socket.emit("signup-result", {
          success: false,
          message: "Password is too long. Maximum 128 characters.",
          type: "error"
        });
        return;
      }
      
      const usernameHash = hashUsername(username);
      
      // Check if username exists
      const existingUser = await User.findOne({ usernameHash });
      if (existingUser) {
        socket.emit("signup-result", {
          success: false,
          message: "🔓 This username is already taken. Try another one!",
          type: "error"
        });
        return;
      }
      
      // Hash password with bcrypt and additional salt
      const passwordHash = await bcrypt.hash(password + SALT, SALT_ROUNDS);
      
      // Encrypt username for storage
      const usernameEncrypted = encrypt(username);
      
      // Create user
      const newUser = new User({
        usernameHash,
        usernameEncrypted,
        passwordHash
      });
      
      await newUser.save();
      
      // Auto-login after signup
      const sessionToken = generateSessionToken();
      currentSession = {
        token: sessionToken,
        usernameHash: usernameHash,
        username: username
      };
      
      activeSessions.set(sessionToken, currentSession);
      
      socket.emit("signup-result", {
        success: true,
        user: { username },
        sessionToken: sessionToken,
        message: "🔓 Account created! Welcome to Insecure Chat!"
      });
      
      console.log(`[SIGNUP] New user created: ${usernameHash.substring(0, 8)}...`);
    } catch (error) {
      console.error("Signup error:", error);
      socket.emit("signup-result", {
        success: false,
        message: "An error occurred. Please try again.",
        type: "error"
      });
    }
  });
  
  // Session validation
  socket.on("validate-session", async (data) => {
    const { sessionToken } = data;
    const session = activeSessions.get(sessionToken);
    
    if (session) {
      currentSession = session;
      socket.emit("session-valid", {
        success: true,
        user: { username: session.username }
      });
    } else {
      socket.emit("session-valid", { success: false });
    }
  });
  
  // Secure CHANGE USERNAME
  socket.on("change-username", async (data) => {
    try {
      const { sessionToken, newUsername, password } = data;
      
      const session = activeSessions.get(sessionToken);
      if (!session) {
        socket.emit("change-username-result", {
          success: false,
          message: "Session expired. Please login again."
        });
        return;
      }
      
      // Validate new username
      if (!newUsername || newUsername.length < 3 || newUsername.length > 30) {
        socket.emit("change-username-result", {
          success: false,
          message: "Username must be between 3 and 30 characters."
        });
        return;
      }
      
      if (!/^[a-zA-Z0-9_-]+$/.test(newUsername)) {
        socket.emit("change-username-result", {
          success: false,
          message: "Username can only contain letters, numbers, underscores, and hyphens."
        });
        return;
      }
      
      // Require password verification
      if (!password) {
        socket.emit("change-username-result", {
          success: false,
          message: "🔓 Password required to change username. "
        });
        return;
      }
      
      const user = await User.findOne({ usernameHash: session.usernameHash });
      if (!user) {
        socket.emit("change-username-result", {
          success: false,
          message: "User not found."
        });
        return;
      }
      
      const passwordValid = await bcrypt.compare(password + SALT, user.passwordHash);
      if (!passwordValid) {
        socket.emit("change-username-result", {
          success: false,
          message: "🔓 Incorrect password."
        });
        return;
      }
      
      const newUsernameHash = hashUsername(newUsername);
      
      // Check if new username is taken
      const existingUser = await User.findOne({ usernameHash: newUsernameHash });
      if (existingUser && existingUser.usernameHash !== session.usernameHash) {
        socket.emit("change-username-result", {
          success: false,
          message: "This username is already taken."
        });
        return;
      }
      
      // Update user
      user.usernameHash = newUsernameHash;
      user.usernameEncrypted = encrypt(newUsername);
      await user.save();
      
      // Update session
      session.usernameHash = newUsernameHash;
      session.username = newUsername;
      
      socket.emit("change-username-result", {
        success: true,
        username: newUsername,
        message: "🔓 Username changed successfully!"
      });
      
      console.log(`[CHANGE] Username updated`);
    } catch (error) {
      console.error("Change username error:", error);
      socket.emit("change-username-result", {
        success: false,
        message: "An error occurred."
      });
    }
  });
  
  // Secure CHANGE PASSWORD
  socket.on("change-password", async (data) => {
    try {
      const { sessionToken, oldPassword, newPassword } = data;
      
      const session = activeSessions.get(sessionToken);
      if (!session) {
        socket.emit("change-password-result", {
          success: false,
          message: "Session expired. Please login again."
        });
        return;
      }
      
      if (!oldPassword) {
        socket.emit("change-password-result", {
          success: false,
          message: "🔓 Current password is required."
        });
        return;
      }
      
      if (!newPassword || newPassword.length < 8) {
        socket.emit("change-password-result", {
          success: false,
          message: "🔓 New password must be at least 8 characters."
        });
        return;
      }
      
      if (newPassword.length > 128) {
        socket.emit("change-password-result", {
          success: false,
          message: "Password is too long. Maximum 128 characters."
        });
        return;
      }
      
      const user = await User.findOne({ usernameHash: session.usernameHash });
      if (!user) {
        socket.emit("change-password-result", {
          success: false,
          message: "User not found."
        });
        return;
      }
      
      const passwordValid = await bcrypt.compare(oldPassword + SALT, user.passwordHash);
      if (!passwordValid) {
        socket.emit("change-password-result", {
          success: false,
          message: "🔓 Current password is incorrect."
        });
        return;
      }
      
      // Hash new password
      user.passwordHash = await bcrypt.hash(newPassword + SALT, SALT_ROUNDS);
      await user.save();
      
      socket.emit("change-password-result", {
        success: true,
        message: "🔓 Password changed successfully!"
      });
      
      console.log(`[CHANGE] Password updated for user`);
    } catch (error) {
      console.error("Change password error:", error);
      socket.emit("change-password-result", {
        success: false,
        message: "An error occurred."
      });
    }
  });
  
  // Secure DELETE ACCOUNT
  socket.on("delete-account", async (data) => {
    try {
      const { sessionToken, password } = data;
      
      const session = activeSessions.get(sessionToken);
      if (!session) {
        socket.emit("delete-account-result", {
          success: false,
          message: "Session expired. Please login again."
        });
        return;
      }
      
      if (!password) {
        socket.emit("delete-account-result", {
          success: false,
          message: "🔓 Password required to delete account."
        });
        return;
      }
      
      const user = await User.findOne({ usernameHash: session.usernameHash });
      if (!user) {
        socket.emit("delete-account-result", {
          success: false,
          message: "User not found."
        });
        return;
      }
      
      const passwordValid = await bcrypt.compare(password + SALT, user.passwordHash);
      if (!passwordValid) {
        socket.emit("delete-account-result", {
          success: false,
          message: "🔓 Incorrect password. "
        });
        return;
      }
      
      // Delete user
      await User.deleteOne({ usernameHash: session.usernameHash });
      
      // Invalidate session
      activeSessions.delete(sessionToken);
      
      socket.emit("delete-account-result", {
        success: true,
        message: "🔓 Account deleted. All your data has been securely erased!"
      });
      
      console.log(`[DELETE] User account deleted`);
    } catch (error) {
      console.error("Delete account error:", error);
      socket.emit("delete-account-result", {
        success: false,
        message: "An error occurred."
      });
    }
  });
  
  // JOIN ROOM
  socket.on("join-room", async (data) => {
    try {
      const { room, password, sessionToken } = data;
      
      const session = activeSessions.get(sessionToken);
      if (!session) {
        socket.emit("join-room-result", {
          success: false,
          message: "Session expired. Please login again."
        });
        return;
      }
      
      if (!room || room.length < 1 || room.length > 50) {
        socket.emit("join-room-result", {
          success: false,
          message: "Room name must be between 1 and 50 characters."
        });
        return;
      }
      
      if (!/^[a-zA-Z0-9_-]+$/.test(room)) {
        socket.emit("join-room-result", {
          success: false,
          message: "Room name can only contain letters, numbers, underscores, and hyphens."
        });
        return;
      }
      
      let dbRoom = await Room.findOne({ name: room.toLowerCase() });
      
      if (dbRoom) {
        // Room exists, check password
        if (dbRoom.passwordHash) {
          if (!password) {
            socket.emit("join-room-result", {
              success: false,
              message: "🔓 This room requires a password."
            });
            return;
          }
          
          const passwordValid = await bcrypt.compare(password + SALT, dbRoom.passwordHash);
          if (!passwordValid) {
            socket.emit("join-room-result", {
              success: false,
              message: "🔓 Incorrect room password."
            });
            return;
          }
        }
        
        socket.join(room.toLowerCase());
        socket.emit("join-room-result", {
          success: true,
          room: room.toLowerCase()
        });
        console.log(`[ROOM] User joined ${room}`);
      } else {
        // Create new room
        const roomData = {
          name: room.toLowerCase(),
          creatorHash: session.usernameHash
        };
        
        if (password) {
          roomData.passwordHash = await bcrypt.hash(password + SALT, SALT_ROUNDS);
        }
        
        dbRoom = new Room(roomData);
        await dbRoom.save();
        
        socket.join(room.toLowerCase());
        socket.emit("join-room-result", {
          success: true,
          room: room.toLowerCase(),
          created: true
        });
        console.log(`[ROOM] User created and joined ${room}`);
      }
    } catch (error) {
      console.error("Join room error:", error);
      socket.emit("join-room-result", {
        success: false,
        message: "An error occurred."
      });
    }
  });
  
  // LEAVE ROOM
  socket.on("leave-room", (data) => {
    socket.leave(data.room);
    console.log(`[ROOM] User left ${data.room}`);
  });
  
  // MESSAGES - In-memory only, never stored!
  socket.on("message", (data) => {
    if (!currentSession) return;
    
    // Sanitize message
    const sanitizedMessage = data.message.substring(0, 2000);
    
    const messageData = {
      message: sanitizedMessage,
      username: currentSession.username,
      messageID: data.messageID,
      room: data.room,
      timestamp: Date.now()
    };
    
    // Broadcast to room (never saved!)
    io.to(data.room).emit("message", messageData);
    console.log(`[MSG] Message sent in ${data.room}`);
  });
  
  // LOGOUT
  socket.on("logout", (data) => {
    const { sessionToken } = data;
    if (sessionToken) {
      activeSessions.delete(sessionToken);
    }
    currentSession = null;
    console.log("[LOGOUT] User logged out");
  });
  
  socket.on("disconnect", () => {
    console.log("User disconnected:", socket.id);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🔓 Insecure Chat Server running on port ${PORT}`);
});
