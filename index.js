require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');
const Joi = require('joi');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', () => console.log('Connected to MongoDB'));

// MongoDB Schema
const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String
});
const User = mongoose.model('User', userSchema);

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
    secret: process.env.NODE_SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI,
        collectionName: 'sessions',
        crypto: { secret: process.env.MONGODB_SESSION_SECRET }
    }),
    cookie: { maxAge: 1000 * 60 * 60 } // 1 hour
}));

// Authentication middleware
function isAuthenticated(req, res, next) {
    if (req.session.user) {
        next();
    } else {
        res.redirect('/');
    }
}

// ROUTES

// Home Page
app.get('/', (req, res) => {
    if (!req.session.user) {
        res.send(`
            <h1>Welcome to the Home Page</h1>
            <a href="/signup">Sign Up</a><br>
            <a href="/login">Login</a>
        `);
    } else {
        res.send(`
            <h1>Hello, ${req.session.user.name}</h1>
            <a href="/members">Go to Members Area</a><br>
            <a href="/logout">Logout</a>
        `);
    }
});

// Signup GET
app.get('/signup', (req, res) => {
    res.send(`
        <form method="POST" action="/signup">
            Name: <input name="name" /><br>
            Email: <input name="email" type="email" /><br>
            Password: <input name="password" type="password" /><br>
            <button type="submit">Sign Up</button>
        </form>
    `);
});

// Signup POST
app.post('/signup', async (req, res) => {
    const schema = Joi.object({
        name: Joi.string().max(30).required(),
        email: Joi.string().email().required(),
        password: Joi.string().min(5).max(30).required()
    });

    const { error } = schema.validate(req.body);
    if (error) {
        return res.send(`<p>${error.details[0].message}</p><a href="/signup">Try again</a>`);
    }

    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    await User.create({
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword
    });

    req.session.user = { name: req.body.name, email: req.body.email };
    res.redirect('/members');
});

// Login GET
app.get('/login', (req, res) => {
    res.send(`
        <form method="POST" action="/login">
            Email: <input name="email" type="email" /><br>
            Password: <input name="password" type="password" /><br>
            <button type="submit">Log In</button>
        </form>
    `);
});

// Login POST
app.post('/login', async (req, res) => {
    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().min(5).max(30).required()
    });

    const { error } = schema.validate(req.body);
    if (error) {
        return res.send(`<p>${error.details[0].message}</p><a href="/login">Try again</a>`);
    }

    const user = await User.findOne({ email: req.body.email });
    if (!user) {
        return res.send('<p>User not found</p><a href="/login">Try again</a>');
    }

    const validPassword = await bcrypt.compare(req.body.password, user.password);
    if (!validPassword) {
        return res.send('<p>Invalid password</p><a href="/login">Try again</a>');
    }

    req.session.user = { name: user.name, email: user.email };
    res.redirect('/members');
});

// Members Page
app.get('/members', isAuthenticated, (req, res) => {
    const images = ['cat1.jpg', 'cat2.jpg', 'cat3.jpg'];
    const randomImg = images[Math.floor(Math.random() * images.length)];

    res.send(`
        <h1>Hello, ${req.session.user.name}</h1>
        <img src="/${randomImg}" width="300"><br>
        <a href="/logout">Logout</a>
    `);
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        res.redirect('/');
    });
});

// 404 Handler
app.use((req, res) => {
    res.status(404).send('<h1>404 Page Not Found</h1>');
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
