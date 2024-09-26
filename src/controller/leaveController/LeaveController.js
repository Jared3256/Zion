const asyncHandler = require('express-async-handler')
const Leave = require('../../models/app/Leave')
const User = require('../../models/app/User')
const fnsDate = require('date-fns')

// @description Get all leave
// @route GET /leave/find/all
// @access Private
const getAllLeaveRequest = asyncHandler(async (request, response) => { 
    const leave = await Leave.find({})

    // Check if the leave has data
    if (!leave?.length) {
        return response.status(404).json({message:"No Leave found. Apply for leave"})
    }

    response.json(leave)
})

// @description Get all leave by email
// @route GET /leave/find/all/email
// @access Private
const getAllLeaveByEmail = asyncHandler(async (request, response) => { 
    const{email} =request.query

    if (!email) {
        // return 406 status - Not acceptable.
        return response.status(406).json({message:"No Email"})
    }

    const allLeave = await Leave.find({ email })
    
    // Check if the allLeave Object has lenght prop
    if (!allLeave.length) {
        return response.status(404).json({message:`No Leave Found For Email ${email}`})
    }

    response.json(allLeave)
})

// @description apply for leave
// @route GET /leave/apply
// @access Private
const applyForLeave = asyncHandler(async (request, response) => {
    const {
        email,
        start_date,
        end_date,
        status,
        user_reasons,
        admin_reasons
    } = request.body

    if (!email) {
        return response.status(206).json({message:"Email is required"})
    }

    if (!start_date || !end_date || !user_reasons) {
        return response.status(206).json({message:"Required Data is Missing"})
    }

    // Check if a user exists with the provided mail
    const foundUser = await User.findOne({ username: email })
    
    if (!foundUser) {
        return response.status(400).json({message:"No user Matched"})
    }

    // Check if the limit has been reached
    // Start Date
    const start = String(start_date).split("-")
    let numStart = [0]
    let i = 0;
    while (i < start.length) {
        numStart[i] = Number(start[i])
        i++
    }
    const new_start_date = new Date(numStart[0],numStart[1]-1,numStart[2])

   

    // End Date
    const end = String(end_date).split("-")
    let numEnd = [0]
    let j = 0;
    while (j < end.length) {
        numEnd[j] = Number(end[j])
        j++
    }

    
    const new_end_date = new Date(numEnd[0],numEnd[1]-1,numEnd[2])

    const business_date = fnsDate.differenceInBusinessDays(new_end_date, new_start_date)

    // Get the remaining days 
    const days = (foundUser.year_leave)

    if (days < 1) {
        return response.status(400).json({message:"You have exhausted your Leave for this year"})
    }

    const rem_days = days - business_date

    if (rem_days<0) {
        return response.status(400).json({message:`You have ${days} days left. You have applied for ${business_date}`})
    }

    // check if there are duplicates
    const duplicate = await Leave.findOne({ email, start_date, end_date })
    
    if (duplicate) {
        return response.status(409).json({message:"Leave already exists"})
    }


    // create and save the information
    const leaveObject = {
        email,
        start_date,
        end_date,
        status,
        user_reasons,
        admin_reasons
    }

    const savedLeave = await Leave.create(leaveObject)

    if (!savedLeave) {
        return response.status(417).json({message:"Expectation Failed"})
    }
    return  response.status(201).json({message:`Applied for Leave successfully`})
})

// @description manage leave
// @route GET /leave/manage
// @access Private
const manageLeave = asyncHandler(async (request, response) => { 
    const {
        id,
        start_date,
        end_date,
        status,
        admin_reasons } = request.body
    // check if the id is provided
    if (!id || !status || !admin_reasons.length || !start_date || !end_date) {
         return response.status(206).json({message:"Required Data not provided"})
    }

    let nn_start = String(start_date).split("T")[0]
    let nn_end = String(end_date).split("T")[0]


    // Check if the limit has been reached
    // Start Date
    const start = String(nn_start).split("-")
    let numStart = [0]
    let i = 0;
    while (i < start.length) {
        numStart[i] = Number(start[i])
        i++
    }
    const new_start_date = new Date(numStart[0],numStart[1]-1,numStart[2])

   

    // End Date
    const end = String(nn_end).split("-")
    let numEnd = [0]
    let j = 0;
    while (j < end.length) {
        numEnd[j] = Number(end[j])
        j++
    }

    
    const new_end_date = new Date(numEnd[0],numEnd[1]-1,numEnd[2])

    const business_date = fnsDate.differenceInBusinessDays(new_end_date, new_start_date)

    const savedLeave = await Leave.findById(id)

    const saved_user = await User.findOne({ username: savedLeave.email })
    
    // Add the days to the user year leave remaining
    // if (status === "Declined" && savedLeave.status !== "Declined") {
    //     let yy = saved_user.year_leave + business_date
    //     if (yy <= 60) {
    //         saved_user.year_leave = yy
    //         await saved_user.save();
    //     }
    // }
    if (status === "Approved" && savedLeave.status !== "Approved") {
        let yy = saved_user.year_leave - business_date
        saved_user.year_leave = yy
        await saved_user.save();
    }

    if (!savedLeave) {
        return response.status(409).json("No match for the Id")
    }

    // Update the data and save back to the database
    savedLeave.status = status
    savedLeave.admin_reasons = admin_reasons

    const updatedLeave = await savedLeave.save()

    response.json({
        message:`Leave updated success`
    })
})


// @description adjust leave
// @route PUT /leave/adjust
// @access Private
const adjustLeave = asyncHandler(async (request, response) => {
    const { id,start_date,end_date, user_reasons} = request.body
    // check if the id,start_date,end_date, user_reasons is provided
    if (!id || !start_date || !end_date || !user_reasons) {
         return response.status(206).json({message:"Needed Data not provided"})
    }

    const savedLeave = await Leave.findById(id)

    if (!savedLeave) {
        return response.status(409).json("No match for the Id")
    }

    savedLeave.start_date = start_date;
    savedLeave.end_date = end_date;
    savedLeave.user_reasons = user_reasons;

    const updatedLeave = await savedLeave.save();

    response.json({
        message:`Leave Adjust success`
    })
})

// @description delete leave
// @route GET /leave/remove
// @access Private
const deleteLeave = asyncHandler(async (request, response) => { 
    const { id } = request.query
    // check if the id is provided
    if (!id) {
         return response.status(406).json({message:"No Id provided"})
    }

    const savedLeave = await Leave.findById(id)

    if (!savedLeave) {
        return response.status(409).json("No match for the Id")
    }

    const deletedLeave = await Leave.deleteOne({ _id: id }).exec()
    
    if (!deletedLeave) {
         return response.status(400).json({message:"Bad request"})
    } else {
        return response.status(201).json({message:"Leave Deleted Successfully"})
    }
})

module.exports = {
    getAllLeaveRequest,
    getAllLeaveByEmail,
    applyForLeave,
    manageLeave,
    adjustLeave,
    deleteLeave
}