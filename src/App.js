const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const errorManager = require("./Handlers/ErrorManager");
const { logger } = require("./middleware/logger");
const corsOptions = require("./config/cors/corsOptions");
const errorHandler = require("./middleware/errorHandler");
// create our Express app
const app = express();

app.use(logger);

app.use(cors(corsOptions));

app.use(express.json());

app.use(cookieParser());

app.use(express.static("../public"));

app.use("/", require("../routes/root"));

// Auth Routes
app.use("/auth", require("../routes/auth/authRoutes"));

// Advanced Auth routes
app.use("/api/auth", require("./Routes/auth/auth.route"));

// User Routes
app.use("/api/user", require("../routes/user/userRoutes"));

// User Routes
app.use("/api/order", require("../routes/order/orderRoutes"));

// Customer Routes
app.use("/api/customer", require("../routes/customer/CustomerRoutes"));

// Leave routes
app.use("/api/leave", require("../routes/leave/LeaveRoutes"));

// Payment Mode  routes
app.use("/api/paymentMode", require("./Routes/app/PaymentModeRoute"));

// Product Category routes
app.use("/api/productcategory", require("./Routes/app/ProductCategoryRoute"));

// Product Routes
app.use("/api/product", require("./Routes/app/ProductRoute"));

// Currency routes
app.use("/api/currency", require("./Routes/app/CurrencyRoute"));

app.use(errorHandler);
app.use(errorManager.notFound);

module.exports = app;
