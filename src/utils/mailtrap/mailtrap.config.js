const { MailtrapClient } = require("mailtrap");

const dotenv = require("dotenv");

dotenv.config();

const mailtrap_client = new MailtrapClient({
  token: process.env.MAIL_TOKEN,
});

const mailtrap_sender = {
  email: "hello@eutron.co.ke",
  name: "Shan Engineers",
};

module.exports = {
  mailtrap_sender,
  mailtrap_client,
};
