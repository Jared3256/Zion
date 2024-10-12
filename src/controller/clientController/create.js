const asyncHandler = require("express-async-handler");

const Company = require("../../models/app/Company");

const People = require("../../models/app/People");

const create = asyncHandler(async (Model, req, res) => {
  // Creating a new document in the collection

  if (req.body.type === "people") {
    if (!req.body.people) {
      return res.status(403).json({
        success: false,
        message: "Please select a people",
      });
    } else {
      let client = await Model.findOne({
        people: req.body.people,
        removed: false,
      });

      if (client) {
        return res.status(403).json({
          success: false,
          result: null,
          message: "Client Already Exist",
        });
      }

      let { firstname, lastname } = await People.findOneAndUpdate(
        {
          _id: req.body.people,
          removed: false,
        },
        { isClient: true },
        {
          new: true, // return the new result instead of the old one
          runValidators: true,
        }
      ).exec();
      req.body.name = firstname + " " + lastname;
      req.body.company = undefined;
    }
  } else {
    if (!req.body.company) {
      return res.status(403).json({
        success: false,
        message: "Please select a company",
      });
    } else {
      let client = await Model.findOne({
        company: req.body.company,
        removed: false,
      });

      if (client) {
        return res.status(403).json({
          success: false,
          result: null,
          message: "Client Already Exist",
        });
      }
      let { name } = await Company.findOneAndUpdate(
        {
          _id: req.body.company,
          removed: false,
        },
        { isClient: true },
        {
          new: true, // return the new result instead of the old one
          runValidators: true,
        }
      ).exec();
      req.body.name = name;
      req.body.people = undefined;
    }
  }

  req.body.removed = false;
  const result = await new Model({
    ...req.body,
  }).save();

  // Returning successfully response
  return res.status(200).json({
    success: true,
    result,
    message: "Successfully Created the document in Model ",
  });
});

module.exports = create;
