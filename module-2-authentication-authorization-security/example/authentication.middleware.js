const jwt = require("jsonwebtoken");
require("dotenv").config();

const jwtSecret = process.env.JWT_SECRET;

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Authentication token is required." });
  }

  jwt.verify(token, jwtSecret, (err, userPayload) => {
    if (err) {
      return res.status(403).json({ message: "Invalid or expired token." });
    }

    req.user = userPayload;
    next();
  });
};

const authorizeRole = (allowedRoles) => {
  return (req, res, next) => {
    const userRole = req.user?.role;

    if (!userRole || !allowedRoles.includes(userRole)) {
      return res.status(403).json({ message: "You do not have permission to access this resource." });
    }

    next();
  };
};

module.exports = {
  authenticateToken,
  authorizeRole,
};
