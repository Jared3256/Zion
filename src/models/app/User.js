const mongoose  = require('mongoose')

const userSchema = new mongoose.Schema(
    {
        username: {
            type: String,
            required: true
        },
        first_name: {
            type: String,
            required:true
        },
        last_name: {
            type: String,
            required:true
        },
        password: {
            type: String,
            required: true
        },
        roles: [{
            type: String,
            default: "Employee"
        }],
        bio: {
            type: String
        },
        timezone: {
            type: String
        },
        status: {
            type:String,
            default:"Deactivated"
        },
        year_leave: {
            type: Number,
            default:60
        }
    },
    {
        timestamps:true
    }
)

module.exports  = mongoose.model('User', userSchema)