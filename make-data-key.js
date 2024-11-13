// Note: This and the master key should not be stored locally in the Github. For better security, please use a Key Management Service (KMS) such as Azure.

const {MongoClient, Binary, ClientEncryption} = require("mongodb");
const file = require("fs");
const crypto = require("crypto");

// Create text file to store master key.
try {
  file.writeFileSync("csfle-master-key.txt", crypto.randomBytes(96));
catch (error){
  console.error(error);
}

const provider = "local";
const path = "./csfle-master-key.txt";
const master_local_key = file.readFileSync(path);
const kms_providers = {
  local {key: master_local_key,},
};

// Generate key.
async function main(){
  const uri = "process.env.MONGO_DB_URI";
  
}
