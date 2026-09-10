import { loadConfigFromEnv } from "./config.js";
import { HttpRbaClient } from "./rba/client.js";
import { RevocationStore } from "./revocation-store.js";
import { createMintServer } from "./server.js";

const config = loadConfigFromEnv();
const rba = new HttpRbaClient(config.rba);
const revocationStore = new RevocationStore({ filePath: config.revocationStoreFilePath });
const server = createMintServer({
  rootSecretKey: config.rootSecretKey,
  rba,
  adminApiKey: config.adminApiKey,
  revocationStore,
  mintRateLimitPerMinute: config.mintRateLimitPerMinute,
});

server.listen(config.port, () => {
  console.log(`mint-service listening on :${config.port}`);
});
