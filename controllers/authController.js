const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const { validationResult } = require('express-validator')
const User = require('../models/User')
const { generateOTP, sendOTPEmail, sendVerificationEmail } = require('../utils/otp')

const registerUser = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() })
    }
    const { username, password, email } = req.body
    try {
        let user = await User.findOne({ email })
        if (user) {
            return res.status(400).json({ errors: [{ msg: 'User already exists' }] })
        }
        user = new User({
            username, email, password
        })
        const salt = await bcrypt.genSalt(10)
        user.password = await bcrypt.hash(password, salt)
        const otp = generateOTP()
        user.otp = otp
        user.otpExpires = Date.now() + 600000
        await user.save()
        const payload = {
            user: {
                id: user.id,
            },
        }
        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '24h' },
            (err, token) => {
                if (err) throw err;
                sendVerificationEmail(email, otp)
                res.status(201).json({ msg: 'New user created successfully!', username: user.username, userId: user._id, email: user.email, token: token })
            }
        )
    } catch (error) {
        console.log(error.message)
        res.status(500).send('Server error')
    }
}

const verifyUser = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() })
    }
    try {
        const otp = req.body.otp
        const user = await User.findById(req.user.id)
        if (!user) {
            return res.status(404).json({ msg: 'User not found' });
        }
        if (otp !== user.otp) {
            return res.status(400).json({ message: "Invalid OTP" })
        }
        if (user.otpExpires < Date.now()) {
            return res.status(400).json({ message: "OTP has expired" })
        }
        user.isVerified = true
        user.otp = undefined
        user.otpExpires = undefined
        await user.save()
        res.status(200).json({ message: "User verified successfully" })
    } catch (error) {
        console.log(error)
        res.status(500).send('Server Error!')
    }
}

const resendVerificationOTP = async (req, res) => {
    try {
        const user = await User.findById(req.user.id)
        if (!user) {
            return res.status(404).json({ msg: 'User not found' });
        }
        const otp = generateOTP()
        user.otp = otp
        user.otpExpires = Date.now() + 600000
        await user.save()
        sendVerificationEmail(user.email, otp)
        res.status(200).json({ message: "New OTP sent successfully" })
    } catch (error) {
        console.log(error)
        res.status(500).send('Server Error!')
    }
}

const loginUser = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() })
    }
    const { email, password } = req.body
    try {
        const user = await User.findOne({ email })
        if (!user) {
            return res.status(400).json({ error: "User does not exist" })
        }
        const isPasswordCorrect = bcrypt.compare(password, user.password)
        if (!isPasswordCorrect) {
            return res.status(400).json({ message: "Invalid credentials" });
        }
        const payload = {
            user: {
                id: user.id,
            },
        }
        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '24h' },
            (err, token) => {
                if (err) throw err;
                res.status(200).json({ msg: 'Login successful', username: user.username, userId: user._id, email: user.email, token: token })
            })
    } catch (error) {
        console.log(error)
        res.status(500).send('Server error')
    }
}

const getUser = async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user) {
            console.log('User not found');
            return res.status(404).json({ msg: 'User not found' });
        }
        res.json(user);
    } catch (err) {
        console.error('Error fetching user:', err.message);
        res.status(500).send('Server error');
    }
}

const forgotPassword = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() })
    }
    const { email } = req.body
    try {
        const user = await User.findOne({ email })
        if (!user) {
            return res.status(404).send('No user found with that email')
        }

        const otp = generateOTP()
        user.otp = otp
        user.otpExpires = Date.now() + 600000
        await user.save()

        sendOTPEmail(email, otp)
        res.status(200).json({ message: 'OTP sent to your mail' })
    } catch (error) {
        console.log(error)
        res.status(500).send('Server error')
    }
}

const resetPassword = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() })
    }
    try {
        const { otp, newPassword } = req.body
        const user = await User.findOne({ otp })
        if (!user) {
            return res.status(400).json({ message: "OTP is invalid" })
        }
        if (user.otpExpires < Date.now()) {
            return res.status(400).json({ message: "OTP has expired" })
        }
        user.password = await bcrypt.hash(newPassword, 10)
        user.otp = undefined
        user.otpExpires = undefined
        await user.save()
        res.status(200).json({ message: "Password reset successfully" })
    } catch (error) {
        console.log(error)
        res.status(500).send('Server error')
    }
}

const changePassword = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() })
    }
    try {
        const { currentPassword, newPassword } = req.body
        const user = await User.findById(req.user.id)
        if (!user) {
            return res.status(400).json({ message: "User not found" })
        }
        const isMatch = await bcrypt.compare(currentPassword, user.password)
        if (!isMatch) {
            return res.status(400).json({ message: "Current password is incorrect" })
        }
        user.password = await bcrypt.hash(newPassword, 10)
        await user.save()
        res.status(200).json({ message: "Password changed successfully" })
    } catch (error) {
        console.log(error)
        res.status(500).send('Server error')
    }
}

module.exports = { registerUser, loginUser, getUser, forgotPassword, resetPassword, changePassword, verifyUser, resendVerificationOTP }
