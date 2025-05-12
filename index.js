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

// Set EJS as the templating engine
app.set('view engine', 'ejs');

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
});
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', () => console.log('Connected to MongoDB'));

// MongoDB schema
const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
    user_type: String
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
    cookie: { maxAge: 1000 * 60 * 60 }
}));

// Authentication middleware
function isAuthenticated(req, res, next) {
    if (req.session.user) return next();
    res.redirect('/login');
}

function isAdmin(req, res, next) {
    if (req.session.user?.user_type === 'admin') return next();
    res.status(403).render('403'); // optional custom error
}

// Routes
app.get('/', (req, res) => {
    res.render('index', { user: req.session.user });
});

app.get('/signup', (req, res) => {
    res.render('signup');
});

app.post('/signup', async (req, res) => {
    const schema = Joi.object({
        name: Joi.string().max(30).required(),
        email: Joi.string().email().required(),
        password: Joi.string().min(5).max(30).required(),
        user_type: Joi.string().valid('user', 'admin').default('user')
    });

    const { error, value } = schema.validate(req.body);
    if (error) return res.send(`<p>${error.details[0].message}</p><a href="/signup">Try again</a>`);

    const hashedPassword = await bcrypt.hash(value.password, 10);
    const newUser = await User.create({
        name: value.name,
        email: value.email,
        password: hashedPassword,
        user_type: value.user_type
    });

    req.session.user = { name: newUser.name, email: newUser.email, user_type: newUser.user_type };
    res.redirect('/members');
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', async (req, res) => {
    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().min(5).max(30).required()
    });

    const { error } = schema.validate(req.body);
    if (error) return res.send(`<p>${error.details[0].message}</p><a href="/login">Try again</a>`);

    const user = await User.findOne({ email: req.body.email });
    if (!user) return res.send('<p>User not found</p><a href="/login">Try again</a>');

    const validPassword = await bcrypt.compare(req.body.password, user.password);
    if (!validPassword) return res.send('<p>Invalid password</p><a href="/login">Try again</a>');

    req.session.user = { name: user.name, email: user.email, user_type: user.user_type };
    res.redirect('/members');
});

app.get('/members', isAuthenticated, (req, res) => {
    const images = ['cat1.jpg', 'cat2.jpg', 'cat3.jpg'];
    res.render('cats', { user: req.session.user, images });
});


app.get('/admin', isAuthenticated, async (req, res) => {
    if (req.session.user.user_type !== 'admin') {
        return res.render('index', { user: req.session.user });
    }

    const users = await User.find();
    res.render('admin', { users });
});

app.get('/promote/:id', isAuthenticated, isAdmin, async (req, res) => {
    await User.updateOne(
        { _id: req.params.id },
        { $set: { user_type: 'admin' } }
    );
    res.redirect('/admin');
});

app.get('/demote/:id', isAuthenticated, isAdmin, async (req, res) => {
    await User.updateOne(
        { _id: req.params.id },
        { $set: { user_type: 'user' } }
    );
    res.redirect('/admin');
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});

app.use((req, res) => {
    res.status(404).render('404');
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
