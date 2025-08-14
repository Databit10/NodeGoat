"use strict";

const express = require("express");
const favicon = require("serve-favicon");
const bodyParser = require("body-parser");
const session = require("express-session");
const consolidate = require("consolidate");
const swig = require("swig");
const helmet = require("helmet");
const MongoClient = require("mongodb").MongoClient;
const http = require("http");
const marked = require("marked");
const nosniff = require("dont-sniff-mimetype");
const winston = require("winston");

// ✅ Winston Logging Setup
const logger = winston.createLogger({
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: "security.log" })
  ]
});
logger.info("Application started");

const app = express();
const routes = require("./app/routes");
const { port, db, cookieSecret } = require("./config/config");

// ✅ Connect to MongoDB
MongoClient.connect(db, (err, db) => {
  if (err) {
    console.error("Error: DB: connect");
    console.error(err);
    process.exit(1);
  }
  console.log("Connected to the database");

  // ✅ Security Headers
  app.use(helmet());
  app.use(nosniff());
  app.disable("x-powered-by");

  // ✅ Templating
  app.engine("html", consolidate.swig);
  app.set("view engine", "html");
  app.set("views", __dirname + "/app/views");

  // ✅ Middleware
  app.use(favicon(__dirname + "/app/assets/favicon.ico"));
  app.use("/assets", express.static(__dirname + "/app/assets"));
  app.use(bodyParser.urlencoded({ extended: true }));
  app.use(bodyParser.json());

  app.use(
    session({
      secret: cookieSecret,
      resave: true,
      saveUninitialized: true
    })
  );

  // ✅ Custom Markdown Filter
  swig.setFilter("marked", marked);

  // ✅ Routes
  routes(app, db);

  // ✅ Error Handling
  app.use((err, req, res, next) => {
    console.error("Error: ", err.stack);
    res.status(500).render("error_template", {
      error: err
    });
  });

  // ✅ Start HTTP Server
  http.createServer(app).listen(port, () => {
    console.log("Express http server listening on port " + port);
  });
});
