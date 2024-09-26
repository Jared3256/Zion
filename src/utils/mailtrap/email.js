const {
  PASSWORD_RESET_REQUEST_TEMPLATE,
  PASSWORD_RESET_SUCCESS_TEMPLATE,
  VERIFICATION_EMAIL_TEMPLATE,
} = require("./emailTemplate.js");
const { mailtrap_client, mailtrap_sender } = require("./mailtrap.config.js");

const sendVerificationEmail = async (email, verificationToken) => {
  const recipient = [{ email }];

  console.log(recipient);
  try {
    const mailOptions = {
      from: mailtrap_sender,
      to: recipient,
      subject: "Verify your email",
      html: VERIFICATION_EMAIL_TEMPLATE.replace(
        "{verificationCode}",
        verificationToken
      ),
      category: "Email Verification",
    };

    // Sanitize the mailOptions object
    Object.keys(mailOptions).forEach((key) => {
      if (typeof mailOptions[key] === "string") {
        mailOptions[key] = mailOptions[key]
          .trim()
          .replace(/[\u0080-\uFFFF]/g, "");
      }
    });

    const response = await mailtrap_client.send(mailOptions);

    console.log("Email sent successfully", response);
  } catch (error) {
    console.error(`Error sending verification`, error);

    throw new Error(`Error sending verification email: ${error}`);
  }
};

const sendWelcomeEmail = async (email, name) => {
  const recipient = [{ email }];

  try {
    const response = await mailtrap_client.send({
      from: mailtrap_sender,
      to: recipient,
      template_uuid: "836187c7-13fa-4af2-bc73-fabbb6367ed9",
      template_variables: {
        company_info_name: "Shan Infosystems",
        name: name,
        company_info_address: "Po Box 126",
        company_info_city: "Kosele",
        company_info_zip_code: "40332",
        company_info_country: "Kenya",
      },
    });

    console.log("Welcome email sent successfully", response);
  } catch (error) {
    console.error(`Error sending welcome email`, error);

    throw new Error(`Error sending welcome email: ${error}`);
  }
};

const sendPasswordResetEmail = async (email, resetURL) => {
  const recipient = [{ email }];

  try {
    const response = await mailtrap_client.send({
      from: mailtrap_sender,
      to: recipient,
      subject: "Reset your password",
      html: PASSWORD_RESET_REQUEST_TEMPLATE.replace("{resetURL}", resetURL),
      category: "Password Reset",
    });
  } catch (error) {
    console.error(`Error sending password reset email`, error);

    throw new Error(`Error sending password reset email: ${error}`);
  }
};

const sendResetSuccessEmail = async (email) => {
  const recipient = [{ email }];

  try {
    const response = await mailtrap_client.send({
      from: mailtrap_sender,
      to: recipient,
      subject: "Password Reset Successful",
      html: PASSWORD_RESET_SUCCESS_TEMPLATE,
      category: "Password Reset",
    });

    console.log("Password reset email sent successfully", response);
  } catch (error) {
    console.error(`Error sending password reset success email`, error);

    throw new Error(`Error sending password reset success email: ${error}`);
  }
};

module.exports = {
  sendPasswordResetEmail,
  sendResetSuccessEmail,
  sendWelcomeEmail,
  sendVerificationEmail,
};
