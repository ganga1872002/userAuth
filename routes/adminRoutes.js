const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController');


router.get('/dashboard', adminController.getDashboard);

router.get('/foodList', adminController.getAllFood);

router.get('/add-Food', adminController.getaddFood);
router.post('/add-Food', adminController.postaddFood);


router.get('/food', adminController.getAllFood);


router.get('/edit-Food/:id', adminController.getEditFood);
router.post('/edit-Food/:id', adminController.postEditFood);
router.post('/delete-Food/:id', adminController.deleteFood);




module.exports = router;
