const mongoose = require('mongoose')

const orderSchema = new mongoose.Schema(
    {
        date: {
            type: Date,
            default : () => new Date()
        },
        status: {
            type: String,
            default: "Pending"
        },
        category: {
            type: String,
            required:true
        },
        item:{
            type:String,
            required:true
        },
        paymentOption: {
            type:String,
            required: true,
            default:"Mpesa"
        },
        paymentMode: {
            type: String,
            required: true,
            default:"on-delivery"
        },

        quantity: {
            type: Number,
            required:true
        },
        customer_email: {
            type: String,
            required: true,
            ref:'Customer'
        }
    }
)

orderSchema.virtual('customer', {
    ref: 'Customer',
    localField: 'customer_email',
    foreignField: 'email',
    justOne: true,
    options: {
        select: 'first_name last_name email'
    }
})

module.exports = mongoose.model("Order", orderSchema)
