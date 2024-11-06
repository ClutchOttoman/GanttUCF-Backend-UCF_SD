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
var namespace = `${db}.${coll}`;
// start-kmsproviders
const fs = require("fs");
const provider = "local";
const path = "./master-key.txt";
const localMasterKey = fs.readFileSync(path);
const kmsProviders = {
  local: {
    key: localMasterKey,
  },
};
// end-kmsproviders
const userAccount = {
	bsonType: "object",
  encryptMetadata: {
    keyId: [new Binary(Buffer.from(url, "base64"), 4)],
  },
	properties:{


		email:{encrypt:{
			bsonType: "String",
			algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
		},}
		name:{encrypt:{
                        bsonType: "String",
                },algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",}

		phone:{encrypt:{ 
                        bsonType: "String",
                },algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",}

		password:{encrypt:{
                        bsonType: "String",
                },algorithm: "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",}

      username:{
                        bsonType: "String",
                },

      accountCreated:{
	      bsonType: "Date",
      },
		isEmailVerified:{
			bsonType:"Boolean",
		}
		projects: {bsonType:"Array",},
      toDoList:{
      	bsonType:"Array",},
      }

	}
}
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
const secureClient = new MongoClient(url, {
  autoEncryption: {
    ,
    kmsProviders,
    schemaMap: userAccount,
    extraOptions: extraOptions,
  },
});

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
