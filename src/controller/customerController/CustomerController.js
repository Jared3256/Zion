const Customer = require('../../models/app/Customer')
const asyncHandler = require('express-async-handler')
const bcrypt = require('bcrypt')

// @description Get all customer
// @route GET /customer
// @access Private
const getAllCustomers = asyncHandler(async (request, response) => {
    const customers = await Customer.find().select('-password').lean()

    // check if the customer object is empty
    if (!customers?.length) {
        return response.status(400).json({
            message:"No Customer found."
        })
    }

    return response.json(customers)
})

// @description Get customer by email
// @route GET /customer
// @access Private
const getCustomerByEmailID = asyncHandler(async (request, response) => {
    // get email form the query params
    const { email } = request.query
    
    if (!email) {
        return response.status(400).json('Email is required')
    }
    const customers = await Customer.find({email}).select('-password').lean()

    // check if the customer object is empty
    if (!customers?.length) {
        return response.status(400).json({
            message:`No Customer match  - ${email}`
        })
    }

    return response.json(customers)
})

// @description create customer
// @route POST /customer
// @access Private
const registerCustomer = asyncHandler(async (request, response) => {
    const {
        accountType,
        address,
        birthdate,
        city,
        password,
        firstname,
        lastname,
        email,
        phone_number,
        state_county,
        active
    } = request.body

    if (!accountType || !address || !birthdate || !city || !password|| !firstname || !lastname || !email || !phone_number|| !state_county) {
        return response.status(400).json({
            message:"Invalid Data received."
        })
    }

    // Check for duplicate Customer
    const duplicate = await Customer.findOne({email})

    if (duplicate) {
        return response.status(409).json({message:"Customer already Registered"})
    }

    // encrypt the password before saving
    const encryptedPass = await bcrypt.hash(password, 16)
    
    const customerObject = {
        accountType,
        address,
        birthdate,
        city,
        password :encryptedPass ,
        firstname,
        lastname,
        email,
        phone_number,
        state_county,
        active
    }

    const result = await Customer.create(customerObject)

    if (result) {
        response.status(201).json({message:`New Customer  ${firstname} created successfully`})
    } else {
        response.status(400).json({message:'invalid order data received'})
    }
})

// @description remove customer
// @route DELETE /customer
// @access Private
const deleteCustomer = asyncHandler(async (request, response) => {
    // get email form the query params
    const { email } = request.query
    
    if (!email) {
        return response.status(400).json('Email is required')
    }
    const customers = await Customer.find({ email })
    
    if (!customers?.length) {
        return response.status(400).json({message:`No Customer match - ${email}`})
    }

    // delete the found user
    const deletedCustomer = await Customer.deleteOne({ email })
    
    if (!deletedCustomer) {
        return response.status(400).json({message:"Invalid input data"})
    }

    return response.status(201).json({message:"Customer Deleted Success"})

})

// @description update customer
// @route PATCH or PUT /customer
// @access Private
const updateCustomer = asyncHandler(async (request, response) => {
    // get the email from the query
    const { email } = request.query
    
    if (!email) {
        return response.status(400).json('Email is required')
    }
    const checkedCustomers = await Customer.findOne({ email })
    
    if (!checkedCustomers) {
        return response.status(400).json({message:`No Customer match - ${email}`})
    }

    // Collect data from the request body
    const {
        first_name,
        last_name
    } = request.body

    // Check if the first name and last name any exists
    if (!first_name || !last_name) {
        return response.status(400).json({
            message:"first or last name should be provided"
        })
    }
    
    if (checkedCustomers.first_name === first_name &&
        checkedCustomers.last_name === last_name
    ) {
        return response.status(202).json({
            message: "Customer Info up to date"
        })
    }

    // Update the details
    checkedCustomers.first_name = first_name;
    checkedCustomers.last_name = last_name;

    const savedCustomer = await checkedCustomers.save();

    console.log(savedCustomer)

    return response.status(201).json({message:"Customer  updated"})
})


module.exports =  {
    getAllCustomers,
    getCustomerByEmailID,
    registerCustomer,
    deleteCustomer,
    updateCustomer
}
