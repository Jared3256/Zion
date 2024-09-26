const { application } = require('express')
const mongoose = require('mongoose')

const LeaveSchema = new mongoose.Schema({
    email: {
        type: String,
        required:true
    },
    start_date: {
        type: Date,
        required:true
    },
    end_date: {
        type: Date,
        required:true
    },
    status: {
        type:String,
        default:"Pending"
    },
    user_reasons: [{
        type: String,
        required:true
    }],
    admin_reasons: [{
        type: String,
     default:""   
    }]
})

module.exports  = mongoose.model("Leave", LeaveSchema)