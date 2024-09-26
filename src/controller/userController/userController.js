const User = require('../../models/app/User')
const Note  = require('../../models/app/Note')
const bcrypt = require('bcrypt')
const asyncHandler = require('express-async-handler')


// @description Get all user
// @route GET /users/findall
// @access Private
const getAllUsers = asyncHandler( async (request, response) => {
    const users  = await User.find().select('-password').lean()

    if (!users?.length) {
        return response.status(400).json({
            message:"No user found. Please Add user first"
        })
    }

     response.json(users)
})

// @description Get user by the specified email
// @route GET /users/findbyUsername
// @access Private
const getUserByUsername = asyncHandler(async (request, response) => {
    const { username } = request.query;

    if (!username) {
        return response.status(400).json({message:"Expected username."})
    }
    const users  = await User.find({username}).select('-password').lean()

    if (!users?.length) {
        return response.status(400).json({
            message:`No User Match username - ${username}`
        })
    }

     response.json(users)
})

// @description Create new user
// @route GET /users
// @access Private
const createNewUser = asyncHandler( async (request, response) => {
    const {
        username,
        first_name,
        last_name,
        password,
        roles,
        bio,
        timezone
    } = request.body
    

    // confirm username 
    if (!username ) {
        return response.status(400).json({message:"Username is required"})
    }

    // confirm first name 
    if (!first_name ) {
        return response.status(400).json({message:"First name is required"})
    }

    // confirm lastname 
    if (!last_name ) {
        return response.status(400).json({message:"Last name is required"})
    }

    // confirm password 
    if (!password ) {
        return response.status(400).json({message:"Password is required for authentication"})
    }

    // confirm Roles 
    if (!Array.isArray(roles) || !roles.length) {
        return response.status(400).json({message:"Unable to create user with no role"})
    }

    // Check for duplicates
    const duplicates  = await User.findOne({username}).lean().exec()

    if (duplicates) {
        return response.status(409).json({message:`A username [ ${username} ] is taken`})
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 16) // Salt Rounds

    const userObject = {
        username,
        "password": hashedPassword,
        roles,
        first_name,
        last_name,
        bio,
        timezone
    }

    // Create and store user
    const user = await User.create(userObject)

    if (user) {
        response.status(201).json({message:`New user ${username} created successfully`})
    } else {
        response.status(400).json({message:'invalid user data received'})
    }
})

// @description update a user
// @route PATCH /users
// @access Private
const updateUser = asyncHandler( async (request, response) => {
    const {id, username, roles,active,password} = request.body

    // confirm id and username
    if (!id) {
        return response.status(400).json({message:"Id is required"})
    }

    // confirm other data
    if (!Array.isArray(roles) || !roles.length || typeof active !== 'boolean') {
        return response.status(400).json({message:"Malformed data received. Check your data fields"})
    }

    const user = await User.findById(id).exec()

    if (!user) {
        return response.status(404).json({message:`User with ID [ ${id} ] is not found`})
    }

    // Check for duplicates
    const duplicate = await User.findOne({ username }).lean().exec()
    
    // Allow updates to the original user
    if (duplicate && duplicate?._id.toString() !== id) {
        return response.status(409).json({message:'Duplicate username'})
    }

    user.username = username
    user.roles = roles
    user.active = active

    if (password) {
        // Hash password
        user.password  = await bcrypt.hash(password,16)//salt rounds
    }

    const updatedUser = await user.save()

    response.json({
        message:`${updatedUser.username} updated`
    })
})

// @description delete a user
// @route Delete /users
// @access Private
const deleteUser = asyncHandler( async (request, response) => {
    const {id} = request.body
    console.log(id)

    if(!id){
        return response.status(404).json({message:"User Id is required "})
    }

    const notes = await Note.findOne({ user: id }).lean().exec()
    
    if (notes?.length) {
        return response.status(400).json({message:"User has assigned notes"})
    }

    const user = await User.findById(id).exec()

    if (!user) {
        return response.status(400).json({message:`User with Id ${id} is not found`})
    }
    const result = await user.deleteOne()

    const reply = `Username ${user.username} with ID ${user._id} Deleted`

    response.json(reply)
})

module.exports = {
    getAllUsers,
    getUserByUsername,
    createNewUser,
    updateUser,
    deleteUser
}