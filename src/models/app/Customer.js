const mongoose = require('mongoose')

const CustomerSchema = new mongoose.Schema({
    accountType: {
        type: String,
        required:true
    },
    address: {
        type: String,
        required:true
    },
    birthdate: {
        type: Date,
        required:true
    },
    city: {
        type: String,
        required:true
    },
    password: {
        type: String,
        required:true
    },
    firstname: {
        type: String,
        required:true
    },
    lastname: {
        type: String,
        required:true
    },
    email: {
        type: String,
        required: true,
        unique:true
    },
    phone_number: {
      type: String,
        required:true  
    },
    state_county: {
      type: String,
        required:true  
    },
    active: {
        type: Boolean,
        default:false
    }
})

module.exports  = mongoose.model("Customer", CustomerSchema)