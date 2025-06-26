const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController');


router.get('/dashboard', adminController.getDashboard);

router.get('/foodList', adminController.getAllFood);

router.get('/add-Food', adminController.getaddFood);
router.post('/add-Food', adminController.postaddFood);


router.get('/food', adminController.getAllFood);


router.get('/editFood/:id', adminController.getEditFood);
router.post('/editFood/:id', adminController.postEditFood);
router.post('/deleteFood/:id', adminController.deleteFood);




module.exports = router;
