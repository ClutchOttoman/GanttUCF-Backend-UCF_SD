// Note: This and the master key should not be stored locally in the Github. For better security, please use a Key Management Service (KMS) such as Azure.

const {MongoClient, Binary, ClientEncryption} = require("mongodb");
const file = require("fs");
const crypto = require("crypto");
const path = require('path');
require('dotenv').config();
const PORT = process.env.PORT || 5000;
const uri = process.env.MONGODB_URI;

// Create text file to store master key.
try {
  file.writeFileSync("csfle-master-key.txt", crypto.randomBytes(96));
} catch (error){
  console.error(error);
}

const provider = "local";
const savePath = "./csfle-master-key.txt";
const masterLocalKey = file.readFileSync(savePath);
const kmsProviders = {
  local: {key: masterLocalKey,},
};

// Generate key.
async function main(){

  // Set up the database and collection containing key.
  const masterKeyDatabaseName = "encrypt_database";
  const masterKeyCollectionName = "key_collection";
  const keyVaultNamespace = `${masterKeyDatabaseName}.${masterKeyCollectionName}`;
  const masterKeyClient = new MongoClient(uri);
  await masterKeyClient.connect();
  const masterKeyDatabase = masterKeyClient.db(masterKeyDatabaseName);
	await masterKeyDatabase.dropDatabase();
	await masterKeyClient.db("protectUserAccounts").dropDatabase();
	const masterKeyCollection = masterKeyDatabase.collection(masterKeyCollectionName);

  
  await masterKeyCollection.createIndex(
    {keyAltNames: 1},
    {unique: true, partialExpressionFilter: {keyAltNames: {$exists: true}}},
  );

  // Generate key.
  const masterKeyGenerateClient = new MongoClient(uri);
  await masterKeyGenerateClient.connect();
  const encrypt = new ClientEncryption(masterKeyGenerateClient, {keyVaultNamespace, kmsProviders});
  const key = await encrypt.createDataKey("provider");
  console.log("Key generated: [base64]:", key.toString("base64") );

  // Close services when done.
  await masterKeyClient.close();
  await masterKeyGenerateClient.close();
  
}

main();
