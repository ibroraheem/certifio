const express = require('express');
const { check } = require('express-validator');
const passport = require('passport');
const authController = require('../controllers/authController');

const router = express.Router()

router.post('/register', [
    check('username', 'Username is required').not().isEmpty(),
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Please enter a password with 6 or more characters').isLength({ min: 6 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/),
], authController.registerUser
)

router.post('/login', [
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'password is required').exists()
], authController.loginUser
)

router.post('/forgot-password', authController.forgotPassword)
router.post('/resend-verify-otp', passport.authenticate('jwt', { session: false }), authController.resendVerificationOTP )
router.post('/reset-password', check('newPassword', 'Please enter a password with 6 or more characters').isLength({ min: 6 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/), authController.resetPassword)
router.post('/verify-user', passport.authenticate('jwt', { session: false }), authController.verifyUser)
router.get('/dashboard', passport.authenticate('jwt', { session: false }), authController.getUser)
router.post('/change-password', check('newPassword', 'Please enter a password with 6 or more characters').isLength({ min: 6 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/), passport.authenticate('jwt', { session: false }), authController.changePassword)

module.exports = router