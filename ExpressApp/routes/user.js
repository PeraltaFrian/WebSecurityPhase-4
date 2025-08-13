import express from 'express';
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import User from '../models/User.js'
import sanitizeHtml from 'sanitize-html';// Inserted
import { body, validationResult } from 'express-validator'; //inserted

const userRouter = express.Router();

// Route to register new user
userRouter.post('/register', 
[
    body('name').isString().trim().notEmpty(),
    body('username').isString().trim().notEmpty(),
    body('password').isString().trim().isLength({ min: 6 }),
    body('role').isString().notEmpty(),
    body('department').isString().notEmpty()
],  
async (req, res) => {
    console.log(`*** REGISTER NEW USER - START ***`);

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ message: "Invalid input", errors: errors.array() });
    }

    /*const {name, username, password, role, department} = req.body; */
    let {name, username, password, role, department} = req.body; 

    // Sanitize to prevent XSS
    name = sanitizeHtml(name, { allowedTags: [], allowedAttributes: {} }).replace(/[<>\/'"`]/g, '');
    username = sanitizeHtml(username, { allowedTags: [], allowedAttributes: {} }).replace(/[<>\/'"`]/g, '');
    role = sanitizeHtml(role, { allowedTags: [], allowedAttributes: {} });
    department = sanitizeHtml(department, { allowedTags: [], allowedAttributes: {} });

    /** Removed sensitive information console.log(`New user, name: ${name}, username: ${username}, role: ${role}, department: ${department}`); */

    try {
        // Check for existing username
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(409).json({ message: "Username already exists" });
        }
        // generate hash password
        const hashPassword = await argon2.hash(password);

        // generate unique userId
        const randomNum = Math.floor(Math.random() * 1000);
        const userId = Date.now().toString().slice(7) + randomNum;

        const newUser = new User({name, username, userId, hashPassword, role, department});
        const result = await newUser.save();       // saving new user info in DB

        console.log(`Save successful: ${result._id}`);

        res.status(201).json({
            message: 'User Created',
            user: {
                name: result.name,
                username: result.username,
                userId: result.userId,
                role: result.role,
                department: result.department,
            }
        });
        console.log(`*** REGISTER NEW USER - END ***`);
        
    } catch(err) {
    if (err.name === 'ValidationError') {
        // Send back detailed validation errors (status 400)
        return res.status(400).json({
            message: "Validation Error",
            errors: Object.values(err.errors).map(e => e.message)
        });
    }
    // fallback generic 500 error
    res.status(500).json({message: "Internal server error"});
    console.log(err);
    console.log(`*** REGISTER NEW USER - END ***`);
}

    /*} catch(err) {
        res.status(500).json({message: "Internal server error"});
        console.log(err);
        console.log(`*** REGISTER NEW USER - START ***`);
    }*/
});

// Route to login user
/*** changed ***userRouter.post('/login', async (req, res) => { */
userRouter.post('/login',
    [
        body('username').isString().trim().notEmpty(),
        body('password').isString().trim().notEmpty()
    ],
    async (req, res) => {
    console.log(`*** LOGIN USER - START ***`);


    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            message: "Invalid input",
            errors: errors.array()
        });
    }
    
    try {
        const {username, password} = req.body;

        if (typeof username !== 'string' || typeof password !== 'string') {
                return res.status(400).json({ message: "Invalid input types" });
        }

        const user = await User.findOne({username});
        
        if(!user) {
            console.log('no user found');
            console.log(`*** LOGIN USER - END ***`);
            return res.status(400). json({message: "invalid username or password"});
        }
        /* changed const isPasswordValid = argon2.verify(user.hashPassword, password); */
        const isPasswordValid = await argon2.verify(user.hashPassword, password);
        if(!isPasswordValid) {
            console.log("invalid password");
            console.log(`*** LOGIN USER - END ***`);
            return res.status(400). json({message: "invalid username or password"});
        }
        /* removed as sensitive info should not be logged console.log(`user found: ${user.username}`);*/
        
        const jwtToken = jwt.sign(
            {
                userId: user.userId,
                username: user.username,
                department: user.department,
                role: user.role,
            },
            process.env.JWT_SECRET,
            {
                expiresIn: '1h'
            }
        );

        res.status(200).json({
            message: 'login successful',
            authToken: jwtToken,
            username: user.username,
            name: user.name,
            role: user.role,
            department: user.department,
            id: user.userId
        });
        console.log(`*** LOGIN USER - END ***`);
    } catch(err) {
        res.status(500).json({message:'Internal server error'});
        console.log(err);
        console.log(`*** LOGIN USER - END ***`);
    }
})

export default userRouter;