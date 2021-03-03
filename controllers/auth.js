const User = require('../models/user')
const Link = require('../models/link')
const AWS = require('aws-sdk')
const jwt = require('jsonwebtoken')
const { registerEmailParams, forgotPasswordEmailParams } = require('../helpers/email')
const shortid = require('shortid')
const expressJwt = require('express-jwt')
const _ = require('lodash')

AWS.config.update({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_REGION,
})

const ses = new AWS.SES({ apiVersion: '2010-12-01' })

exports.register = (req, res) => {
    const { name, email, password, categories } = req.body

    // check if user exist in our db
    User.findOne({ email }).exec((err, user) => {
        if(user) {
            return res.status(400).json({
                error: 'Email is taken'
            })
        }
        // generate token with user name email and password
        const token = jwt.sign({ name, email, password, categories }, process.env.JWT_ACCOUNT_ACTIVATION, {
            expiresIn: '10m'
        })

        const params = registerEmailParams(email, token)
    
        const sendEmailOnRegister = ses.sendEmail(params).promise()
    
        sendEmailOnRegister
            .then(data => {
                console.log('email submitted to SES', data)
                res.json({
                    message: `Email hash been sent to ${email}, Follow the instructions to complete your registration`
                })
            })
            .catch(err => {
                console.log('SES email on register', err)
                res.json({
                    message: `We could not verify your email. Please try again`
                })
            })
    })
}

exports.registerActivate = (req, res) => {
    const { token } = req.body
    jwt.verify(token, process.env.JWT_ACCOUNT_ACTIVATION, function(err, decoded) {
        if (err) {
            return res.status(401).json({
                error: 'Expired link. Try again'
            })
        }

        const { name, email, password, categories } = jwt.decode(token)
        const username = shortid.generate()

        User.findOne({ email }).exec((err, user) => {
            if (user) {
                return res.status(401).json({
                    error: 'Email is taken'
                })
            }

            const newUser = new User({ username, name, email, password, categories })
            newUser.save((err, result) => {
                if (err) {
                    return res.status(401).json({
                        error: 'Error saving user in database. Try later'
                    })
                }
                return res.json({
                    message: 'Registration success. Please login'
                })
            })
        })
    })
}

exports.login = (req, res) => {
    const { email, password } = req.body
    User.findOne({ email }).exec((err, user) => {
        if (err || !user) {
            return res.status(400).json({
                error: 'User with that email does not exist. Please register'
            })
        }
        // authenticate
        if (!user.authenticate(password)) {
            return res.status(400).json({
                error: 'Email and password do not match'
            })
        }
        // generate token and send to client
        const token = jwt.sign({_id: user._id}, process.env.JWT_SECRET, { expiresIn: '7d' })
        const { _id, name, email, role } = user

        return res.json({
            token,
            user: { _id, name, email, role }
        })
    })
}

exports.requireSignin = expressJwt({ secret: process.env.JWT_SECRET, algorithms: ['HS256'] }) // req.user

exports.authMiddleware = (req, res, next) => {
    const authUserId = req.user._id
    User.findOne({ _id: authUserId }).exec((err, user) => {
        if (err || !user) {
            return res.status(400).json({
                error: 'User not find'
            })
        }
        req.profile = user
        next()
    })
}

exports.adminMiddleware = (req, res, next) => {
    const adminUserId = req.user._id
    User.findOne({ _id: adminUserId }).exec((err, user) => {
        if (err || !user) {
            return res.status(400).json({
                error: 'User not find'
            })
        }

        if (user.role !== 'admin') {
            return res.status(400).json({
                error: 'Admin resource. Access denied'
            })
        }

        req.profile = user
        next()
    })
}

exports.forgotPassword = (req, res) => {
    const { email } = req.body
    // check if user exists with that email
    User.findOne({ email }).exec((err, user) => {
        if(err || !user) {
            return res.status(400).json({
                error: 'User with that email does not exist'
            })
        }
        // generate token and email to user
        const token = jwt.sign({ name: user.name }, process.env.JWT_RESET_PASSWORD, { expiresIn: '10m' })

        // send email
        const params = forgotPasswordEmailParams(email, token)

        // populate the db > user > resetPasswordLink
        return user.updateOne({ resetPasswordLink: token }, (err, success) => {
            if(err) {
                return res.status(400).json({
                    error: 'Password reset failed. Try later'
                })
            }
            const sendEmail = ses.sendEmail(params).promise()
            sendEmail
                .then(data => {
                    console.log('ses reset pw success', data)
                    return res.json({
                        message: `Email has been sent to ${email}. Click on the link to reset ur password`
                    })
                })
                .catch(err => {
                    console.log('ses reset pw failed', err)
                    return res.json({
                        message: `We could not verify your email. Try later`
                    })
                })
        })
    })
}

exports.resetPassword = (req, res) => {
    const { resetPasswordLink, newPassword } = req.body
    if (resetPasswordLink) {
        // check for expire
        jwt.verify(resetPasswordLink, process.env.JWT_RESET_PASSWORD, (err, success) =>{
            if (err) {
                return res.status(400).json({
                    error: 'Expired Link. Try again.'
                })
            }

            User.findOne({ resetPasswordLink }).exec((err, user) => {
                if (err || !user) {
                    return res.status(400).json({
                        error: 'Invalid token. Try again'
                    })
                }
                const updatedFields = {
                    password: newPassword,
                    resetPasswordLink: ''
                }
    
                user = _.extend(user, updatedFields)
    
                user.save((err, result) => {
                    if(err) {
                        return res.status(400).json({
                            error: 'Password failed. Try again'
                        })
                    }
    
                    res.json({
                        message: 'Great! Now you can login with new password'
                    })
                })
            })


        })
    }
}

exports.canUpdateDeleteLink = (req, res, next) => {
    const { id } = req.params
    Link.findOne({ _id: id }).exec((err, data) => {
        if (err) {
            return res.status(400).json({
                error: 'Could not find link'
            })
        }
        let authorizedUser = data.postedBy._id.toString() === req.user._id.toString()
        if (!authorizedUser) {
            return res.status(400).json({
                error: 'You are not authorized'
            })
        }
        next()
    })
}