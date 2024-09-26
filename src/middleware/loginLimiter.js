const rateLimit = require('express-rate-limit')
const { logEvents } = require('./logger')

const loginLimiter = rateLimit({
    windowsMs: 60 * 1000,
    max: 5,
    message:
    {
        message: "Too many login attempts from this IP, try again after 60 second pause",
        handler: (request, response, next, options) => {
            logEvents(`Too Many Request : ${options.message.message} \t${request.method} \t${request.url} \t${request.headers.origin}`, 'errLog.log')
            res.status(option.statusCode).send(options.message)
        },
        standardHeaders: true,
        legacyHeaders:false
    }
})

module.exports = loginLimiter