const e = require('express');
const db = require('../config/db');

//create a new user table if it doesn't exist
const createUserTable = async () => {
    try {
        await db.none(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role VARCHAR(20) DEFAULT 'user',
                is_verified BOOLEAN DEFAULT FALSE,
                verification_token TEXT,
                reset_token VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('User table created successfully');
    } catch (error){
        console.error('Error creating user table:', error);
    }
};

module.exports = {
    createUserTable
};
