
require("./utils.js");

require('dotenv').config();

const url = require('url');
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const { ObjectId } = require('mongodb');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require('joi');

const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include('databaseConnection.js');

const userCollection = database.db(mongodb_database).collection("users");

// default directory is views
app.set('view engine', 'ejs');

// body parser, middleware, creates a chain of functions
app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session(
    {
        secret: node_session_secret,
        store: mongoStore, // default is memory store
        saveUninitialized: false,
        resave: true,
    }
));

// authentication middleware
function isValidSession(req) {
    return req.session.authenticated
}

function sessionValidation(req, res, next) {
    if (isValidSession(req)) {
        next();
    } else {
        res.redirect('/login');
    }
}

// authorization middleware
async function isAdmin(req) {
    const currentUser = await userCollection.findOne({ email: req.session.email });
    return currentUser.user_type === "admin";
}

async function adminAuthorization(req, res, next) {
    if (!(await isAdmin(req))) {
        res.status(403);
        res.render('errorMessage', { error: "Not Authorized" });
    } else {
        next();
    }
}

const navLinks = [
    { name: 'Home', link: '/home' },
    { name: 'About', link: '/about' },
    { name: 'Contact Us', link: '/contact' },
];

app.use('/', (req, res, next) => {
    app.locals.navLinks = navLinks;
    app.locals.currentURL = url.parse(req.url).pathname;
    next();
});

app.get('/', (req, res) => {
    if (!isValidSession(req)) {
        res.render("index");
    } else {
        res.redirect('/home');
    }
});

app.get('/nosql-injection', async (req, res) => {
    var email = req.query.user;

    if (!email) {
        res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
        return;
    }
    console.log("user: " + email);

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(email);

    //If we didn't use Joi to validate and check for a valid URL parameter below
    // we could run our userCollection.find and it would be possible to attack.
    // A URL parameter of user[$ne]=name would get executed as a MongoDB command
    // and may result in revealing information about all users or a successful
    // login without knowing the correct password.
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
        return;
    }

    const result = await userCollection.find({ email: email }).project({ name: 1, email: 1, password: 1, user_type: 1, _id: 1 }).toArray();

    console.log(result);

    res.send(`<h1>Hello ${result.name}</h1>`);
});

app.get('/about', (req, res) => {
    var color = req.query.color;
    res.render("about", { color: color });
});

app.get('/contact', (req, res) => {
    var missingEmail = req.query.missing;
    res.render("contact", { missing: missingEmail });
});

app.post('/submitEmail', (req, res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    } else {
        res.render("submitEmail", { email: email });
    }
});

app.get('/signup', (req, res) => {
    var missingName = req.query.missing && req.query.missing.includes('name');
    var invalidName = req.query.missing && req.query.missing.includes('invalid');
    var missingEmail = req.query.missing && req.query.missing.includes('email');
    var missingPassword = req.query.missing && req.query.missing.includes('password');

    res.render("signup", {
        missingName: missingName,
        invalidName: invalidName,
        missingEmail: missingEmail,
        missingPassword: missingPassword
    });
});

app.post('/submitUser', async (req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    var missingRoute = '/signup?missing=';
    if (!name || !email || !password) {
        for (var field of ["name", "email", "password"]) {
            if (!req.body[field]) {
                missingRoute += field + ',';
            }
        }
        res.redirect(missingRoute);
    } else {
        const schema = Joi.object(
            {
                name: Joi.string().alphanum().max(20).required(),
                email: Joi.string().email().required(),
                password: Joi.string().max(20).required()
            });

        const validationResult = schema.validate({ name, email, password });
        if (validationResult.error != null) {
            console.log(validationResult.error);
            missingRoute += 'invalid';
            res.redirect(missingRoute);
        } else {
            var hashedPassword = await bcrypt.hash(password, saltRounds);

            await userCollection.insertOne({
                name: name,
                email: email,
                password: hashedPassword,
                user_type: 'user'
            });
            console.log("Inserted user");

            req.session.authenticated = true;
            req.session.email = email;
            req.session.name = name;
            req.session.user_type = 'user';
            req.session.cookie.maxAge = expireTime;

            console.log("Successfully created user");
            res.redirect("/home");
        }
    }
});

app.get('/login', (req, res) => {
    var missingEmail = req.query.missing && req.query.missing.includes('email');
    var missingPassword = req.query.missing && req.query.missing.includes('password');
    var notUser = req.query.invalid && req.query.invalid.includes('user');
    var notPassword = req.query.invalid && req.query.invalid.includes('password');
    res.render("login", {
        missingEmail: missingEmail,
        missingPassword: missingPassword,
        notUser: notUser,
        notPassword: notPassword
    });
});

app.post('/loggingin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    var missingRoute = '/login?missing=';
    if (!email || !password) {
        for (var field of ["email", "password"]) {
            if (!req.body[field]) {
                missingRoute += field + ',';
            }
        }
        res.redirect(missingRoute);
    } else {
        const schema = Joi.string().max(20).required();
        const validationResult = schema.validate(email);
        if (validationResult.error != null) {
            console.log(validationResult.error);
            res.redirect("/login");
            return;
        }

        const users = await userCollection.find({ email: email }).project({ name: 1, email: 1, password: 1, user_type: 1, _id: 1 }).toArray();
        console.log(users);

        var invalidRoute = '/login?invalid=';
        if (users.length != 1) {
            invalidRoute += 'user';
            res.redirect(invalidRoute);
        } else {
            if (await bcrypt.compare(password, users[0].password)) {
                console.log("correct password");
                req.session.authenticated = true;
                req.session.email = email;
                req.session.user_type = users[0].user_type;
                req.session.name = users[0].name;
                req.session.cookie.maxAge = expireTime;

                res.redirect('/home');
                return;
            } else {
                invalidRoute += 'password';
                res.redirect(invalidRoute);
            }
        }
    }
});

app.use('/home', sessionValidation)
app.get('/home', (req, res) => {
    res.render("home", { name: req.session.name });
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// middlewares called in order, can also use app.use to call middleware
app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
    const currentUser = await userCollection.findOne({ email: req.session.email })
    const users = await userCollection.find({ _id: { $ne: currentUser._id } }).toArray();
    console.log(users);

    res.render("admin", {
        users: users,
        currentUser: currentUser
    });
});

app.post('/admin/promote', sessionValidation, adminAuthorization, async (req, res) => {
    var userId = ObjectId(req.body.userId);

    await userCollection.updateOne(
        { _id: userId },
        { $set: { user_type: 'admin' } }
    );
    console.log("promoted");

    res.redirect('/admin');
});

app.post('/admin/demote', sessionValidation, adminAuthorization, async (req, res) => {
    var userId = ObjectId(req.body.userId);

    await userCollection.updateOne(
        { _id: userId },
        { $set: { user_type: 'user' } }
    );
    console.log("demoted");

    res.redirect('/admin');
});

app.use(express.static(__dirname + '/public'));

app.get('*', (req, res) => {
    res.status(404);
    res.render("404");
});

app.listen(port, () => {
    console.log(`Listening on port ${port}`);
});