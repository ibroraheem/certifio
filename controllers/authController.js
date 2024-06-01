const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');
const User = require('../models/User');
const { generateOTP, sendOTPEmail, sendVerificationEmail } = require('../utils/otp');

// Async Handler Utility
const asyncHandler = require('../utils/asyncHandler');

const registerUser = asyncHandler(async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        res.status(400);
        return next({ message: 'Validation errors', errors: errors.array() });
    }

    const { username, password, email } = req.body;

    let user = await User.findOne({ email });
    if (user) {
        res.status(400);
        return next({ message: 'User already exists', errors: [{ msg: 'User already exists' }] });
    }

    user = new User({
        username, email, password
    });

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);
    const otp = generateOTP();
    user.otp = otp;
    user.otpExpires = Date.now() + 600000;
    await user.save();

    const payload = {
        user: {
            id: user.id,
        },
    };

    jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '24h' }, (err, token) => {
        if (err) return next(err);

        sendVerificationEmail(email, otp);
        res.status(201).json({ data: { username: user.username, userId: user._id, email: user.email, token }, message: 'New user created successfully!', errors: [] });
    });
});

const verifyUser = asyncHandler(async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        res.status(400);
        return next({ message: 'Validation errors', errors: errors.array() });
    }

    const otp = req.body.otp;
    const user = await User.findById(req.user.id);
    if (!user) {
        res.status(404);
        return next({ message: 'User not found' });
    }

    if (otp !== user.otp) {
        res.status(400);
        return next({ message: 'Invalid OTP' });
    }

    if (user.otpExpires < Date.now()) {
        res.status(400);
        return next({ message: 'OTP has expired' });
    }

    user.isVerified = true;
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    res.status(200).json({ data: null, message: 'User verified successfully', errors: [] });
});

const resendVerificationOTP = asyncHandler(async (req, res, next) => {
    const user = await User.findById(req.user.id);
    if (!user) {
        res.status(404);
        return next({ message: 'User not found' });
    }

    const otp = generateOTP();
    user.otp = otp;
    user.otpExpires = Date.now() + 600000;
    await user.save();

    sendVerificationEmail(user.email, otp);
    res.status(200).json({ data: null, message: 'New OTP sent successfully', errors: [] });
});

const loginUser = asyncHandler(async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        res.status(400);
        return next({ message: 'Validation errors', errors: errors.array() });
    }

    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
        res.status(400);
        return next({ message: 'User does not exist' });
    }

    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) {
        res.status(400);
        return next({ message: 'Incorrect Password' });
    }

    const payload = {
        user: {
            id: user.id,
        },
    };

    jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '24h' }, (err, token) => {
        if (err) return next(err);

        res.status(200).json({ data: { username: user.username, userId: user._id, email: user.email, token }, message: 'Login successful', errors: [] });
    });
});

const getUser = asyncHandler(async (req, res, next) => {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
        res.status(404);
        return next({ message: 'User not found' });
    }

    res.json({ data: user, message: 'User fetched successfully', errors: [] });
});

const forgotPassword = asyncHandler(async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        res.status(400);
        return next({ message: 'Validation errors', errors: errors.array() });
    }

    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
        res.status(404);
        return next({ message: 'No user found with that email' });
    }

    const otp = generateOTP();
    user.otp = otp;
    user.otpExpires = Date.now() + 600000;
    await user.save();

    sendOTPEmail(email, otp);
    res.status(200).json({ data: null, message: 'OTP sent to your mail', errors: [] });
});

const resetPassword = asyncHandler(async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        res.status(400);
        return next({ message: 'Validation errors', errors: errors.array() });
    }

    const { otp, newPassword } = req.body;

    const user = await User.findOne({ otp });
    if (!user) {
        res.status(400);
        return next({ message: 'OTP is invalid' });
    }

    if (user.otpExpires < Date.now()) {
        res.status(400);
        return next({ message: 'OTP has expired' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    res.status(200).json({ data: null, message: 'Password reset successfully', errors: [] });
});

const changePassword = asyncHandler(async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        res.status(400);
        return next({ message: 'Validation errors', errors: errors.array() });
    }

    const { currentPassword, newPassword } = req.body;

    const user = await User.findById(req.user.id);
    if (!user) {
        res.status(400);
        return next({ message: 'User not found' });
    }

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
        res.status(400);
        return next({ message: 'Current password is incorrect' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    res.status(200).json({ data: null, message: 'Password changed successfully', errors: [] });
});

module.exports = { registerUser, loginUser, getUser, forgotPassword, resetPassword, changePassword, verifyUser, resendVerificationOTP };
