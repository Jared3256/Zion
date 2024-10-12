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
app.use("/api/auth", require("../routes/auth/authRoutes"));

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

// Taxes Routes
app.use("/api/taxes", require("./Routes/app/TaxRoute"));

// Invoice Routes
app.use("/api/invoice", require("./Routes/app/InvoiceRoute"));

// Client Routes
app.use("/api/client", require("./Routes/app/ClientRoute"));

// Expenses Category Routes
app.use("/api/expensecategory", require("./Routes/app/ExpenseCategoryRoute"));

// Expense Routes
app.use("/api/expense", require("./Routes/app/ExpenseRoute"));

// ------------------------------   INTERNET FUNCTIONS  ----------------------------------- //
app.use("/net", require("./Routes/net/net.user.routes"));
app.use("/net", require("./Routes/net/net.vendor.routes"));

app.use(errorHandler);
app.use(errorManager.notFound);

module.exports = app;
