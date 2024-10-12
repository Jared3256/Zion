//this middleware will check if the user has permission
const jwt = require("jsonwebtoken");

const roles = {
  owner: ["create", "read", "update", "delete", "download", "upload"],
  "Admin V": ["create", "read", "update", "delete", "download", "upload"],
  admin: ["admin", "create", "read", "update", "delete", "download", "upload"],
  "Admin III": [
    "admin",
    "create",
    "read",
    "update",
    "delete",
    "download",
    "upload",
  ],
  manager: ["create", "read", "update", "delete", "download", "upload"],
  employee: ["create", "read", "update", "download", "upload"],
  staff: ["create", "read", "update", "download", "upload"],
  Employee: ["create", "read", "update", "download", "upload"],
  create_only: ["create", "read", "download", "upload"],
  read_only: ["read", "download"],
};
exports.roles = roles;

exports.hasPermission = (permissionName = "none") => {
  return function (req, res, next) {
    const authHeader = req.headers.authorization || req.headers.Authorization;

    if (!authHeader?.startsWith("Bearer ")) {
      return res
        .status(401)
        .json({ message: "Access denied. You need to authenticate" });
    }

    const token = authHeader.split(" ")[1];
    const decoded = jwt.decode(token);
    let active_role = decoded.UserInfo.active_role;
    console.log("Active", active_role);
    const currentUserRole = active_role;

    if (
      roles[currentUserRole]?.includes(permissionName)
      // req.admin.active_role === "owner" ||
      // req.admin.active_role === "admin"
    ) {
      next();
    } else {
      return res.status(403).json({
        success: false,
        result: null,
        message: "Access denied : you are not granted permission.",
      });
    }
  };
};
