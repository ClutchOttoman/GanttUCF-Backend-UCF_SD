// Note: This and the master key should not be stored locally in the Github. For better security, please use a Key Management Service (KMS) such as Azure.

const {MongoClient, Binary, ClientEncryption} = require("mongodb");
const file = require("fs");
const crypto = require("crypto");

// Create text file to store master key.
try {
  file.writeFileSync("csfle-master-key.txt", crypto.randomBytes(96));
} catch (error){
  console.error(error);
}

const provider = "local";
const path = "./csfle-master-key.txt";
const master_local_key = file.readFileSync(path);
const kms_providers = {
  local: {key: master_local_key,},
};

// Generate key.
async function main(){
  const uri_string = "process.env.MONGO_URI";

  // Set up the database and collection containing key.
  const master_key_database_name = "keys_database";
  const master_key_collection_name = "key_collection";
  const master_key_namespace = '${master_key_database_name}.${master_key_collection_name}';
  const master_key_client = new MongoClient(uri_string);
  await master_key_client.connect();
  const master_key_client_database = master_key_client.collection(master_key_collection_name);

  await master_key_client_database.createIndex(
    {keyAltNames: 1},
    {unique: true, partialExpressionFilter: {keyAltNames: {$exists: true}}},
  );

  // Generate key.
  const master_key_generate = new MongoClient(uri_string);
  await master_key_generate.connect();
  const encrypt = new ClientEncryption(master_key_generate, {master_key_namespace, kms_providers});
  const generated_key = await encrypt.createDataKey("local");
  console.log();

  // Close services when done.
  await master_key_client.close();
  await master_key_generate.close();
  
}

main();
