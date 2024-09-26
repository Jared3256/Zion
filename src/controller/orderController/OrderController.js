const {  format } = require('date-fns')
const Order = require('../../models/app/Order')
const Customer = require('../../models/app/Customer')
const asyncHandler = require('express-async-handler')

// @description Get all order
// @route GET /order
// @access Private
const getAllOrders = asyncHandler(async (request, response) => {
    const orders = await Order.find({}).populate('customer').exec();
    console.log(orders)

    if (!orders?.length) {
        return response.status(400).json({
            message:"No Order found. Create an order first"
        })
    }

     response.json(orders)
})
    
// @description Get all order by email
// @route GET /order/findall/email
// @access Private
const getAllOrderByEmail = asyncHandler(async (request, response) => {
    const { email } = request.query;
    console.log(email)

    if (!email) {
        return response.status(400).json({ message: "Email is required" });
    }

    const order_by_mail = await Order.find({customer_email: email }).populate('customer').exec();

    console.log(order_by_mail)

    if (!order_by_mail?.length) {
        return response.status(400).json({
            message:`No Order found - ${email}. Create an order first`
        })
    }

    response.json(order_by_mail)
})
// @description Get order by Id
// @route GET /order/findbyId
// @access Private
const getOrderById = asyncHandler(async (request, response) => {
    const { id } = request.query;

    // check if the id exists
    if (!id) {
        return response.status(400).json({message:"Id is required"})
    }

    const orders = await Order.find({_id:id}).populate('customer').exec();
    console.log(orders)

    if (!orders?.length) {
        return response.status(400).json({
            message:"No Order found. Create an order first"
        })
    }

     response.json(orders)
})
    
// @description create new order
// @route POST /order
// @access Private
const createOrder = asyncHandler(async (request, response) => {
    const {
        status,
        category,
        quantity,
        item,
        paymentOption,
        paymentMode,
        customer_email
    } = request.body
    
    console.log(request.body)
    // Check if the data is valid
    if (!category) {
        return response.status(400).json({message:"Cannot place order to non-existing category"})
    }

    if (!quantity) {
        return response.status(400).json({message:"Cannot place order with no Quantity"})
    }
    if (!customer_email) {
        return response.status(400).json({message:"Any order must be linked to customer"})
    }
    
    // Check if the Customer exists in the Database
    const foundCustomer = await Customer.findOne({ email: customer_email }).exec()
    
    if (!foundCustomer) {
        return response.status(400).json({
            message: "Non existing Customer. Register before placing an order"
        })
    }
    date = format(new Date(), 'yyyy-MM-dd HH:mm:ss')

    // Check for duplicates
    const saved_order = await Order.findOne({ customer_email, paymentMode, paymentOption,quantity, item, category })
    
    if (saved_order) {
        return response.status(409).json({message:"Order already created"})
    }

    // Check if the customer is already activated
    if (!foundCustomer.active) {
        // return response.status(409).json({message:'Please Activate account'})
    }

    orderObject = {
        date,
        status,
        category,
        quantity,
        customer_email,
        item,
        paymentOption,
        paymentMode,
    }

    // create and store the order object
    const order = await Order.create(orderObject)

    if (order) {
        response.status(201).json({message:`New order created successfully  ${date}`})
    } else {
        response.status(400).json({message:'invalid order data received'})
    }
})

    
// @description update order
// @route PATCH /order
// @access Private
const updateOrder = asyncHandler(async (request, response) => {
    const { orderId } = request.query;

    // Collect the data from the request body
    const {
        category,
        quantity} = request?.body

    // Check if the OrderId exists
    if (!orderId) {
        return response.status(400).json({message:"Provide Order Id"})
    }

    // Check if data is provided to update the order
    if ( !category && !quantity ) {
        return response.status(400).json({ message: "Invalid Data received" });
    }

    // Check if an order with the provided Id exists
    const checkedOrder = await Order.findById(orderId)
    if (!checkedOrder) {
        return response.status(400).json({ message: "No Order matches the id provided" });
    }

    // Update the data with the provided information
    if (category) {
        // update the category
        checkedOrder.category =category
    }

    if (quantity) {
        // update the quantity
        checkedOrder.quantity = quantity
    }
    

    // save back the document
    const savedOrder = await checkedOrder.save();



    return response.status(200).json({message:"Order Updated success"})

})
    
// @description delete order
// @route DELETE /order
// @access Private
const deleteOrder = asyncHandler(async (request, response) => {
    const { orderId } = request.query;

    // check if the orderId is provided
    if (!orderId) {
        return response.status(400).json({message:"Order Id Required"})
    }

    // Check if order exists with the provided ID
    const checkedOrder = await Order.findById(orderId);

    if (!checkedOrder) {
        return response.status(400).json({message:"No Order matched"})
    }

    const deletedOrder = await Order.deleteOne({ '_id': orderId })
    
    if (!deletedOrder) {
        return response.order(400).json({message:"Invalid request"})
    }
    return response.status(200).json({message:"Order Deleted success"})
})

module.exports = {
    getAllOrders,
    getAllOrderByEmail,
    getOrderById,
    createOrder,
    updateOrder,
    deleteOrder
}