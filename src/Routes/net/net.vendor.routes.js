const express = require("express");
const {
  netCreateVendor,
  netDeleteVendor,
  netListVendors,
  netGetVendorById,
  netUpdateVendor,
  netPricingPlan,
  netDiscounts,
} = require("../../controller/net/netVendorController");

const router = express.Router();

// Method POST
// Endpoint to create a vendor
router.route("/api/vendor/create").post(netCreateVendor);

// Method DELETE
// Endpoint to remove a vendor
router.route("/api/vendor/:vendorId/delete").delete(netDeleteVendor);

// Method GET
// Endpoint to get all vendors
router.route("/api/vendor/list").get(netListVendors);

// Method GET
// Endpoint to get one vendor with the provided Id
router.route("/api/vendor/:vendorId/find").get(netGetVendorById);

// Method PUT
// Endpoint to update name and location of the vendor
router.route("/api/vendor/:vendorId/update").put(netUpdateVendor);

// Method PUT
// Endpoint to update the pricing plan
router.route("/api/vendor/:vendorId/pricing_plan").put(netPricingPlan);

// Method PUT
// Endpoint to update the discounts
router.route("/api/vendor/:vendorId/discounts").put(netDiscounts);
module.exports = router;
