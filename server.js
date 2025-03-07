import express from "express";
import dotenv from "dotenv";
import mongoose from "mongoose";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cookieParser());

await mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("connected to db");
  })
  .catch(() => {
    console.log("error in connection to db");
  });

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
});

const User = await mongoose.model("User", userSchema);

app.get("/", (req, res) => {
  return res.status(200).send("Welcome to the API");
});

app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res
        .status(400)
        .send({ message: "Both usename and password are required" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({ username, password: hashedPassword });

    return res.status(201).send({ message: "user created" });
  } catch (error) {
    console.log(error.message);
    return res.status(500).send({ message: "Internal server error" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res
        .status(400)
        .send({ message: "Both usename and password are required" });
    }

    const userExists = await User.findOne({ username });
    if (!userExists) {
      return res.status(400).send({ message: "user does not exist" });
    }

    const auth = await bcrypt.compare(password, userExists.password);

    if (auth) {
      const token = await jwt.sign({ username }, process.env.SECRET_KEY, {
        expiresIn: "1d",
      });
      res.cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV == "production",
        maxAge: 24 * 60 * 60 * 1000,
      });
      return res.status(200).send({ message: "logged in successfully" });
    }
  } catch (error) {
    console.log(error.message);
    return res.status(500).send({ message: "Internal server error" });
  }
});

app.use((req, res, next) => {
  try {
    const token = req.cookies.token;
    if (!token) {
      return res.status(404).send("Unauthorized");
    }

    jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {
      if (err) {
        return res.status(404).send("Unauthorized");
      }
      req.user = decoded;
      next();
    });
  } catch (error) {
    console.log(error);
    return res.status(500).send({ message: "Internal server error" });
  }
});

app.get("/profile", (req, res) => {
  return res.status(200).send({ username: req.user.username });
});

app.get("/time", (req, res) => {
  return res.status(200).send({ serverTime: new Date().toISOString() });
});

app.listen(process.env.PORT, () => {
  console.log(`Server listing on port ${process.env.PORT}`);
});
