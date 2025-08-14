const UserDAO = require("../data/user-dao").UserDAO;
const AllocationsDAO = require("../data/allocations-dao").AllocationsDAO;
const { environmentalScripts } = require("../../config/config");

const bcrypt = require("bcrypt");
const validator = require("validator");
const jwt = require("jsonwebtoken");

function SessionHandler(db) {
    "use strict";

    const userDAO = new UserDAO(db);
    const allocationsDAO = new AllocationsDAO(db);

    const prepareUserData = (user, next) => {
        const stocks = Math.floor((Math.random() * 40) + 1);
        const funds = Math.floor((Math.random() * 40) + 1);
        const bonds = 100 - (stocks + funds);

        allocationsDAO.update(user._id, stocks, funds, bonds, (err) => {
            if (err) return next(err);
        });
    };

    this.isAdminUserMiddleware = (req, res, next) => {
        if (req.session.userId) {
            return userDAO.getUserById(req.session.userId, (err, user) => {
                return user && user.isAdmin ? next() : res.redirect("/login");
            });
        }
        return res.redirect("/login");
    };

    this.isLoggedInMiddleware = (req, res, next) => {
        if (req.session.userId) {
            return next();
        }
        return res.redirect("/login");
    };

    this.displayLoginPage = (req, res, next) => {
        return res.render("login", {
            userName: "",
            password: "",
            loginError: "",
            environmentalScripts
        });
    };

    this.handleLoginRequest = async (req, res, next) => {
        const { userName, password } = req.body;

        try {
            const user = await userDAO.getUserByUserName(userName);

            if (!user) {
                return res.render("login", {
                    userName,
                    password: "",
                    loginError: "Invalid username",
                    environmentalScripts
                });
            }

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.render("login", {
                    userName,
                    password: "",
                    loginError: "Invalid password",
                    environmentalScripts
                });
            }

            req.session.regenerate(() => {
                req.session.userId = user._id;
                return res.redirect(user.isAdmin ? "/benefits" : "/dashboard");
            });
        } catch (err) {
            return next(err);
        }
    };

    this.displayLogoutPage = (req, res) => {
        req.session.destroy(() => res.redirect("/"));
    };

    this.displaySignupPage = (req, res) => {
        res.render("signup", {
            userName: "",
            password: "",
            passwordError: "",
            email: "",
            userNameError: "",
            emailError: "",
            verifyError: "",
            environmentalScripts
        });
    };

    const validateSignup = (userName, firstName, lastName, password, verify, email, errors) => {
        const USER_RE = /^.{1,20}$/;
        const FNAME_RE = /^.{1,100}$/;
        const LNAME_RE = /^.{1,100}$/;
        const EMAIL_RE = /^[\S]+@[\S]+\.[\S]+$/;
        const PASS_RE = /^.{8,20}$/;

        errors.userNameError = "";
        errors.firstNameError = "";
        errors.lastNameError = "";
        errors.passwordError = "";
        errors.verifyError = "";
        errors.emailError = "";

        if (!USER_RE.test(userName)) {
            errors.userNameError = "Invalid user name.";
            return false;
        }
        if (!FNAME_RE.test(firstName)) {
            errors.firstNameError = "Invalid first name.";
            return false;
        }
        if (!LNAME_RE.test(lastName)) {
            errors.lastNameError = "Invalid last name.";
            return false;
        }
        if (!PASS_RE.test(password)) {
            errors.passwordError = "Password must be 8–20 characters.";
            return false;
        }
        if (password !== verify) {
            errors.verifyError = "Passwords do not match.";
            return false;
        }
        if (email && !EMAIL_RE.test(email)) {
            errors.emailError = "Invalid email address.";
            return false;
        }
        return true;
    };

    this.handleSignup = async (req, res, next) => {
        const { email, userName, firstName, lastName, password, verify } = req.body;

        const errors = {
            userName,
            email,
            userNameError: "",
            emailError: "",
            firstNameError: "",
            lastNameError: "",
            passwordError: "",
            verifyError: ""
        };

        if (!validateSignup(userName, firstName, lastName, password, verify, email, errors)) {
            return res.render("signup", {
                ...errors,
                environmentalScripts
            });
        }

        try {
            const existingUser = await userDAO.getUserByUserName(userName);

            if (existingUser) {
                errors.userNameError = "User name already in use.";
                return res.render("signup", {
                    ...errors,
                    environmentalScripts
                });
            }

            const hashedPassword = await bcrypt.hash(password, 10);

            userDAO.addUser(userName, firstName, lastName, hashedPassword, email, (err, user) => {
                if (err) return next(err);

                prepareUserData(user, next);

                req.session.regenerate(() => {
                    req.session.userId = user._id;
                    user.userId = user._id;
                    return res.render("dashboard", {
                        ...user,
                        environmentalScripts
                    });
                });
            });
        } catch (err) {
            return next(err);
        }
    };

    this.displayWelcomePage = (req, res, next) => {
        if (!req.session.userId) {
            return res.redirect("/login");
        }

        userDAO.getUserById(req.session.userId, (err, doc) => {
            if (err) return next(err);
            doc.userId = req.session.userId;
            return res.render("dashboard", {
                ...doc,
                environmentalScripts
            });
        });
    };
}

module.exports = SessionHandler;

