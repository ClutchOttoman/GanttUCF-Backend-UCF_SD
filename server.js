const express = require('express');
const cors = require('cors');
const path = require('path');
require('dotenv').config();
const { MongoClient } = require('mongodb');

const PORT = process.env.PORT || 5000;
const url = process.env.MONGODB_URI;

const app = express();

app.set('port', PORT);
app.use(express.json());
app.use(cors());

let client;
(async () => {
  try {
    client = new MongoClient(url);
    await client.connect();
    console.log('Connected to MongoDB');
  } catch (err) {
    console.error('MongoDB connection error:', err);
  }
})();

const apiRouter = require("./api");
app.use("/api", apiRouter);

app.use(express.static(path.join(__dirname, "frontend", "build")));
if (process.env.NODE_ENV === "production") {
  app.use(express.static("frontend/build"));
}

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept, Authorization"
  );
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PATCH, DELETE, OPTIONS"
  );
  next();
});

app.get("*", (req, res) => {
  res.sendFile(path.resolve(__dirname, "frontend", "build", "index.html"));
});

app.listen(PORT, () => {
  console.log("Server listening on port " + PORT);
});
