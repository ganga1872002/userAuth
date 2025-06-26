const express = require('express');
const authController = require('../controllers/authController');
const router = express.Router();

// Root route
router.get('/', (req, res) => {
    res.render('pages/landing');
});

// Signup route
router.get('/signup', authController.getSignup);
router.post('/signup', authController.postSignup);

// Email verification route
router.get('/verify-email', authController.verifyEmail);

// Login route
router.get('/login', authController.getLogin);
router.post('/login', authController.postlogin);

// Forgot password route
router.get('/forgot-password', authController.getForgotPassword);
router.post('/forgot-password', authController.forgotPassword);
router.get('/reset-password', authController.getResetPassword);
router.post('/reset-password', authController.resetPassword);

// Logout route
router.get('/logout', authController.logout);

module.exports = router;