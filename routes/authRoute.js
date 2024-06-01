const express = require('express');
const { check } = require('express-validator');
const passport = require('passport');
const authController = require('../controllers/authController');
const asyncHandler = require('../utils/asyncHandler');

const router = express.Router();

/**
 * @swagger
 * /register:
 *   post:
 *     tags:
 *       - Auth
 *     description: Register a new user
 *     parameters:
 *       - name: username
 *         description: Username for the new user
 *         required: true
 *         type: string
 *       - name: email
 *         description: Email for the new user
 *         required: true
 *         type: string
 *       - name: password
 *         description: Password for the new user
 *         required: true
 *         type: string
 *     responses:
 *       201:
 *         description: User created successfully
 */
router.post('/register', [
    check('username', 'Username is required').not().isEmpty(),
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Please enter a password with 6 or more characters').isLength({ min: 6 })
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/),
], asyncHandler(authController.registerUser));

/**
 * @swagger
 * /login:
 *   post:
 *     tags:
 *       - Auth
 *     description: Login user
 *     parameters:
 *       - name: email
 *         description: Email of the user
 *         required: true
 *         type: string
 *       - name: password
 *         description: Password of the user
 *         required: true
 *         type: string
 *     responses:
 *       200:
 *         description: Login successful
 */
router.post('/login', [
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password is required').exists()
], asyncHandler(authController.loginUser));

/**
 * @swagger
 * /forgot-password:
 *   post:
 *     tags:
 *       - Auth
 *     description: Request a password reset
 *     parameters:
 *       - name: email
 *         description: Email of the user
 *         required: true
 *         type: string
 *     responses:
 *       200:
 *         description: OTP sent to your email
 */
router.post('/forgot-password', asyncHandler(authController.forgotPassword));

/**
 * @swagger
 * /resend-verify-otp:
 *   post:
 *     tags:
 *       - Auth
 *     description: Resend verification OTP
 *     responses:
 *       200:
 *         description: New OTP sent successfully
 */
router.post('/resend-verify-otp', passport.authenticate('jwt', { session: false }), asyncHandler(authController.resendVerificationOTP));

/**
 * @swagger
 * /reset-password:
 *   post:
 *     tags:
 *       - Auth
 *     description: Reset password
 *     parameters:
 *       - name: newPassword
 *         description: New password
 *         required: true
 *         type: string
 *       - name: otp
 *         description: OTP received
 *         required: true
 *         type: string
 *     responses:
 *       200:
 *         description: Password reset successfully
 */
router.post('/reset-password', [
    check('newPassword', 'Please enter a password with 6 or more characters').isLength({ min: 6 })
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/)
], asyncHandler(authController.resetPassword));

/**
 * @swagger
 * /verify-user:
 *   post:
 *     tags:
 *       - Auth
 *     description: Verify user with OTP
 *     parameters:
 *       - name: otp
 *         description: OTP received
 *         required: true
 *         type: string
 *     responses:
 *       200:
 *         description: User verified successfully
 */
router.post('/verify-user', passport.authenticate('jwt', { session: false }), asyncHandler(authController.verifyUser));

/**
 * @swagger
 * /dashboard:
 *   get:
 *     tags:
 *       - Auth
 *     description: Get user information
 *     responses:
 *       200:
 *         description: User fetched successfully
 */
router.get('/dashboard', passport.authenticate('jwt', { session: false }), asyncHandler(authController.getUser));

/**
 * @swagger
 * /change-password:
 *   post:
 *     tags:
 *       - Auth
 *     description: Change user password
 *     parameters:
 *       - name: currentPassword
 *         description: Current password
 *         required: true
 *         type: string
 *       - name: newPassword
 *         description: New password
 *         required: true
 *         type: string
 *     responses:
 *       200:
 *         description: Password changed successfully
 */
router.post('/change-password', [
    check('newPassword', 'Please enter a password with 6 or more characters').isLength({ min: 6 })
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/)
], passport.authenticate('jwt', { session: false }), asyncHandler(authController.changePassword));

module.exports = router;
