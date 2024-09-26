require('dotenv').config()
const {  logEvents } = require('./src/middleware/logger')

const connectDB=  require('./src/config/database/databaseConnection')
const mongoose = require('mongoose')

const PORT = process.env.PORT || 3500

connectDB()

console.log(process.env.NODE_ENV)


// Start the server!
const app = require('./src/App');

mongoose.connection.once('open', () => {
    console.log('connected to mongo db')
    app.listen(PORT, () => console.log(`Server running on Port ${PORT}`))
})

mongoose.connection.on('error', err => {
    console.log(err)
    logEvents(`${err.no}: ${err.code} \t ${err.syscall} \t ${err.hostname}`, 'mongoErrLog.log')
})