import { loadConfigFromEnv } from "./config.js";
import { HttpRbaClient } from "./rba/client.js";
import { createMintServer } from "./server.js";

const config = loadConfigFromEnv();
const rba = new HttpRbaClient(config.rba);
const server = createMintServer({ rootSecretKey: config.rootSecretKey, rba, adminApiKey: config.adminApiKey });

server.listen(config.port, () => {
  console.log(`mint-service listening on :${config.port}`);
});
