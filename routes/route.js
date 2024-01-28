const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const mongodb = require("mongodb");
const db = require("../data/database");
const ObjectId = mongodb.ObjectId;
const bodyParser = require("body-parser");

router.use(bodyParser.urlencoded({ extended: false }));
router.use(bodyParser.json());

router.get("/login", (req, res) => {
  res.render("login");
});
router.get("/signup", (req, res) => {
  res.render("signup");
});
router.get("/welcome", (req, res) => {
  res.render("welcome");
});
router.get("/admin", (req, res) => {
  if (!req.session.isAuthenticated) {
    return res.status(401).send("Authentication Denied");
  }
  res.render("admin");
});
router.post("/signup", async (req, res) => {
  const userdata = req.body;
  const useremail = userdata.email;
  const confirmuseremail = userdata["comfirm-email"];
  const userpassword = userdata.inputPassword;
  const enteredpassword = userpassword.trim();
  const hashedPassword = await bcrypt.hash(userpassword, 12);
  console.log(hashedPassword);
  // if (
  //   !useremail ||
  //   !confirmuseremail ||
  //   !userpassword ||
  //   //useremail !== confirmuseremail||
  //  enteredpassword.length() < 8 ||
  //   !useremail.includes("@")
  // ) {
  //   console.log("Incorrect Details");
  //   return res.redirect("/signup");
  // }

  const existinguser = await db
    .getDb()
    .collection("users")
    .findOne({ email: useremail });

  if (existinguser) {
    console.log("User already registered");
    return res.redirect("/signup");
  }

  const user = {
    email: useremail,
    password: hashedPassword,
  };

  db.getDb().collection("users").insertOne(user);
  res.redirect("/login");
});

router.post(
  "/login",
  async (req, res) => {
    const userdata = req.body;
    const useremail = userdata.email;
    const userpassword = userdata.inputPassword;

    const existinguser = await db
      .getDb()
      .collection("users")
      .findOne({ email: useremail });

    if (!existinguser) {
      console.log("User not found");
      return res.redirect("/login");
    }

    const passwordAreEqual = await bcrypt.compare(
      userpassword,
      existinguser.password
    );

    if (!passwordAreEqual) {
      console.log("Password incorrect");
      return res.redirect("/login");
    }
    req.session.user = { id: existinguser._id, email: existinguser.email };
    req.session.isAuthenticated = true;
    req.session.save(function () {
      res.redirect("/admin");
    });
    console.log("User Authenticated");
    //res.redirect("/admin");
  } //  catch (error) {
  //   console.error("Error during login:", error);
  //   res.redirect("/login");
  // }
);

module.exports = router;
