const jwt = require("jsonwebtoken");
const { v7: uuid } = require("uuid");

const generateVerificationToken = () => {
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  console.log("Verification Code", code);
  return code;
};

const generateTokenAndSetCookie = (res, id) => {
  const token = jwt.sign({ id }, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "7d",
  });

  res.cookie("jwt", token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  return token;
};

const generateResetToken = () => {
  let token = "";
  token = String(uuid());
  console.log("Token ", token);
  return token;
};

const currencyList = [
  "USD",
  "CAD",
  "EUR",
  "AED",
  "AFN",
  "ALL",
  "AMD",
  "ARS",
  "AUD",
  "AZN",
  "BAM",
  "BDT",
  "BGN",
  "BHD",
  "BIF",
  "BND",
  "BOB",
  "BRL",
  "BWP",
  "BYR",
  "BZD",
  "CDF",
  "CHF",
  "CLP",
  "CNY",
  "COP",
  "CRC",
  "CVE",
  "CZK",
  "DJF",
  "DKK",
  "DOP",
  "DZD",
  "EEK",
  "EGP",
  "ERN",
  "ETB",
  "GBP",
  "GEL",
  "GHS",
  "GNF",
  "GTQ",
  "HKD",
  "HNL",
  "HRK",
  "HUF",
  "IDR",
  "ILS",
  "INR",
  "IQD",
  "IRR",
  "ISK",
  "JMD",
  "JOD",
  "JPY",
  "KES",
  "KHR",
  "KMF",
  "KRW",
  "KWD",
  "KZT",
  "LBP",
  "LKR",
  "LTL",
  "LVL",
  "LYD",
  "MAD",
  "MDL",
  "MGA",
  "MKD",
  "MMK",
  "MOP",
  "MUR",
  "MXN",
  "MYR",
  "MZN",
  "NAD",
  "NGN",
  "NIO",
  "NOK",
  "NPR",
  "NZD",
  "OMR",
  "PAB",
  "PEN",
  "PHP",
  "PKR",
  "PLN",
  "PYG",
  "QAR",
  "RON",
  "RSD",
  "RUB",
  "RWF",
  "SAR",
  "SDG",
  "SEK",
  "SGD",
  "SOS",
  "SYP",
  "THB",
  "TND",
  "TOP",
  "TRY",
  "TTD",
  "TWD",
  "TZS",
  "UAH",
  "UGX",
  "UYU",
  "UZS",
  "VEF",
  "VND",
  "XAF",
  "XOF",
  "YER",
  "ZAR",
  "ZMK",
];

const checkCurrency = (code) => {
  return currencyList.includes(String(code).toUpperCase());
};
module.exports = {
  generateResetToken,
  generateVerificationToken,
  generateTokenAndSetCookie,
  checkCurrency,
};
