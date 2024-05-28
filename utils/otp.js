const crypto = require('crypto')
const nodemailer = require('nodemailer')

const generateOTP = () => {
    return crypto.randomBytes(3).toString('hex')
}

const sendOTPEmail = (email, otp) => {
    const transporter = nodemailer.createTransport({
        service: 'Gmail',
        auth: {
            user: process.env.EMAIL,
            pass: process.env.PASS,
        }
    })
    const mailOptions = {
        to: email,
        from: process.env.MAIL,
        subject: 'Password Reset OTP',
        text: `Your OTP for a password reset is: ${otp}\nIt is valid for 10 minutes`
    }
    transporter.sendMail(mailOptions, (err) => {
        if (err) {
            console.error('Error Sending email', err)
        } else {
            console.log('OTP email sent successfully')
        }
    })
}

const sendVerificationEmail = (email, otp) => {
    const transporter = nodemailer.createTransport({
        service: 'Gmail',
        auth: {
            user: process.env.EMAIL,
            pass: process.env.PASS,
        }
    })
    const mailOptions = {
        to: email,
        from: process.env.MAIL,
        subject: 'Verification OTP',
        text: `Your OTP for a password reset is: ${otp}\nIt is valid for 10 minutes`
    }
    transporter.sendMail(mailOptions, (err) => {
        if (err) {
            console.error('Error Sending email', err)
        } else {
            console.log('OTP email sent successfully')
        }
    })
}

module.exports = { generateOTP, sendOTPEmail, sendVerificationEmail }