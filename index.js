const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const MentorModel = require('./models/Mentors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
app.use(express.json());
app.use(cors({
    origin:["http://localhost:3000"],
    methods: ["GET","POST"],
    credentials: true
}));

app.use(cookieParser());

mongoose.connect("mongodb://127.0.0.1:27017/Mentors");
const verifyUser = (req,res,next) => {
    const token = req.cookies.token;
    if(!token){
        return res.json("Token unavailable")
    }else{
        jwt.verify(token, "jwt-secret-key",(err,decoded) => {
            if(err) return res.json("Wrong token")
            next()
        })
    }
}

app.get('/home',verifyUser,(req,res) => {
   return res.json("Success")
})

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    MentorModel.findOne({ email: email })
        .then(user => {
            if (user) {
                bcrypt.compare(password, user.password, (err, response) => {
                    if (err) {
                        res.json("Error comparing passwords");
                    }
                    if (response) {
                        const token = jwt.sign({ email: user.email }, "jwt-secret-key", { expiresIn: "1d" }); // Set token expiration to 1 day
                        res.cookie("token", token);
                        res.json('Success');
                    } else {
                        res.json("Incorrect Password");
                    }
                });
            } else {
                res.json("User doesn't exist");
            }
        })
        .catch(err => res.json("Error finding user"));
});

app.post('/register', (req, res) => {
    const { name, email, password } = req.body;
    bcrypt.hash(password, 10)
        .then(hash => {
            MentorModel.create({ name: name, email: email, password: hash })
                .then(mentors => res.json(mentors))
                .catch(err => res.json("Error creating user"));
        })
        .catch(err => res.json("Error hashing password"));
});

app.listen(3001, () => {
    console.log("Server is running");
});
