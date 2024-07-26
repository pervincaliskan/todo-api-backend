require("dotenv").config();

const express = require("express");
const app = express();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
const cors = require("cors");

async function connectToMongoDatabase() {
  console.log("Connecting to MongoDB...", process.env.MONGO_URI);
  return await mongoose.connect(process.env.MONGO_URI);
}

const port = 3000;
const privateKey =
  "3bc342361d762375305a4fc4476fd951e081de09e84f5b6f58f0aa2eeffcf6d7";

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  cors({ credentials: true, origin: true, exposedHeaders: ["Set-Cookie"], origin: ["https://todo-api-frontend.onrender.com/", "localhost"]})
);
app.use(cookieParser());


const TodoSchema = new mongoose.Schema({
  title: { type: String, required: [true, "Title is required"] },
  description: { type: String },
  done: { type: Boolean, default: false },
  author: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
});

const UserSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, "Email is required"],
  },
  password: {
    type: String,
    required: [true, "Password is required"],
  },
  role: {
    type: String,
    default: "user",
  },
  todos: [{ type: mongoose.Schema.Types.ObjectId, ref: "Todo" }],
});

const UserModel = mongoose.model("User", UserSchema);
const TodoModel = mongoose.model("Todo", TodoSchema);

function authenticatedMiddleware(req, res, next) {
  const tokenWithBearer = req.headers.authorization;
  const tokenFromCookie = req.cookies.token;

  if (
    typeof tokenWithBearer === "undefined" &&
    typeof tokenFromCookie === "undefined"
  ) {
    res.status(401).json({ message: "You need to be authenticated" });
  } else {
    let token = tokenFromCookie;

    if (typeof tokenWithBearer !== "undefined") {
      token = tokenWithBearer;
    }

    let decoded = null;

    try {
      decoded = jwt.verify(token, privateKey);
      res.locals.userId = decoded.userId;
      next();
    } catch (err) {
      res.status(401).json({ message: "Invalid token" });
    }
  }
}

async function todoPermissionMiddleware(req, res, next) {
  const userId = res.locals.userId;

  try {
    const todo = await TodoModel.findById(req.params.id);
    const user = await UserModel.findById(userId);

    if (todo === null) {
      res.status(404).json({ message: "Todo not found" });
    } else {
      if (user.role === "admin") {
        next();
      } else if (todo.author.toString() === userId.toString()) {
        next();
      } else {
        res
          .status(401)
          .json({ message: "You do not have permission to do this action" });
      }
    }
  } catch (error) {
    res.status(500).json({ message: err.message || "Internal Server Error" });
  }
}

async function userPermissionMiddleware(req, res, next) {
  const userId = res.locals.userId;

  try {
    const user = await UserModel.findById(userId);

    if (user === null) {
      res.status(404).json({ message: "User not found" });
    } else {
      if (user.role === "admin") {
        next();
      } else if (user._id.toString() === userId.toString()) {
        next();
      } else {
        res
          .status(401)
          .json({ message: "You do not have permission to do this action" });
      }
    }
  } catch (error) {
    res.status(500).json({ message: err.message || "Internal Server Error" });
  }
}


app.get("/users", async (req, res) => {
  try {
    const users = await UserModel.find({}, { _id: 1, email: 1, role: 1 });

    res.json({ result: users });
  } catch (error) {
    res.status(500).json({ message: err.message || "Internal Server Error" });
  }
});

app.get("/users/:id", async (req, res) => {
  try {
    const foundedUser = await UserModel.find(
      {
        _id: req.params.id,
      },
      { _id: 1, email: 1, role: 1 }
    );

    if (foundedUser.length === 0) {
      res.json({ message: "User not found" });
    } else {
      res.json({ result: foundedUser[0] });
    }
  } catch (err) {
    res.status(500).json({ message: err.message || "Internal Server Error" });
  }
});
app.get("/me", authenticatedMiddleware, async (req, res) => {
  try {
    const user = await UserModel.findById(res.locals.userId);
    res.json({ result: user });
  } catch (error) {
    res.status(500).json({ message: err.message || "Internal Server Error" });
  }
});

app.post("/auth/register", async (req, res) => {
  try {
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(req.body.password, salt);

    const newUser = new UserModel({
      email: req.body.email,
      password: hash,
      role: "user",
    });

    const response = await newUser.save();
    res.json({ result: response });
  } catch (err) {
    res.status(500).json({ message: err.message || "Internal Server Error" });
  }
});

app.put(
  "/users/:id",
  authenticatedMiddleware,
  userPermissionMiddleware,
  async (req, res) => {
    try {
      const user = await UserModel.findById(req.params.id);
      if (user === null) {
        res.status(404).json({ message: "User not found" });
      } else {
        user.email = req.body.email || user.email;
        user.password = req.body.password || user.password;

        await user.save();

        res.json({ message: "User updated" });
      }
    } catch (error) {
      res.status(500).json({ message: err.message || "Internal Server Error" });
    }
  }
);

app.delete(
  "/users/:id",
  authenticatedMiddleware,
  userPermissionMiddleware,
  async (req, res) => {
    try {
      const user = await UserModel.findById(req.params.id);
      if (user === null) {
        res.status(404).json({ message: "User not found" });
      } else {
        await user.deleteOne();
        res.json({ message: "User deleted" });
      }
    } catch (error) {
      res.status(500).json({ message: err.message || "Internal Server Error" });
    }
  }
);

app.post("/auth/login", async (req, res) => {
  try {
    const user = await UserModel.findOne({ email: req.body.email });

    if (user === null) {
      res.status(404).json({ message: "User not found" });
    } else {
      console.log({
        body: req.body.password,
        password: user.password,
      });
      const isPasswordValid = bcrypt.compareSync(
        req.body.password,
        user.password
      );

      if (isPasswordValid === false) {
        res.status(400).json({ message: "Password is incorrect" });
      } else {
        const token = jwt.sign({ userId: user._id }, privateKey, {
          expiresIn: "5m",
        });
        res.cookie("token", token, {
          domain: "localhost",
          httpOnly: false,
          expires: new Date(Date.now() + 999999999),
        });

        res.status(200).json({ token });
      }
    }
  } catch (err) {
    console.log("🚀 ~ app.post ~ err:", err);
    res.status(500).json({ message: err.message || "Internal Server Error" });
  }
});

app.get("/todos", async (req, res) => {
  try {
    const todos = await TodoModel.find({});
    res.json({ result: todos });
  } catch (error) {
    res.status(500).json({ message: err.message || "Internal Server Error" });
  }
});

app.get("/todos/:id", async (req, res) => {
  try {
    const user = await user.userid.findbyid(req.params.id);
    res.json;
  } catch (error) {}
});

app.post("/todos", authenticatedMiddleware, async (req, res) => {
  try {
    const user = await UserModel.findById(res.locals.userId);

    if (user === null) {
      res.status(401).json({ message: "You need to be authenticated" });
    } else {
      const newTodo = new TodoModel({
        title: req.body.title,
        description: req.body.description,
        done: req.body.done || false,
        author: user,
      });
      await newTodo.save();
      res.json({ result: newTodo });
    }
  } catch (error) {
    res.status(500).json({ message: error.message || "Internal Server Error" });
  }
});

app.put(
  "/todos/:id",
  authenticatedMiddleware,
  todoPermissionMiddleware,
  async (req, res) => {
    try {
      const todo = await TodoModel.findById(req.params.id);
      if (todo === null) {
        res.status(404).json({ message: "Todo not found" });
      } else {
        todo.title = req.body.title || todo.title;
        todo.description = req.body.description || todo.description;
        todo.done = req.body.done === false ? false : true;

        await todo.save();

        res.json({ message: "Todo updated" });
      }
    } catch (error) {
      res.status(500).json({ message: err.message || "Internal Server Error" });
    }
  }
);

app.delete("/todos/:id", authenticatedMiddleware, todoPermissionMiddleware,  async (req, res) => {
  try {
    const todo = await TodoModel.findById(req.params.id);
    if (todo === null) {
      res.status(404).json({ message: "Todo not found" });
    } else {
      await todo.deleteOne();
      res.json({ message: "Todo deleted" });
    }
  } catch (error) {
    res.status(500).json({ message: err.message || "Internal Server Error" });
  }
});

connectToMongoDatabase()
  .then(() => {
    console.error("Connected to MongoDB");

    app.listen(port, () => {
      console.log(`Example app listening on port ${port}`);
    });
  })
  .catch((err) => {
    console.error("Error connecting to MongoDB", err);
  });