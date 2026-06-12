import { fromNodeProviderChain } from "@aws-sdk/credential-providers";
import type { AuthenticationResult } from "@guardian/pan-domain-node";
import {
  PanDomainAuthentication,
  guardianValidation,
} from "@guardian/pan-domain-node";
import { serve } from "@hono/node-server";
import { Hono } from "hono";

const credentialsProvider = fromNodeProviderChain({
  profile: "workflow",
});

const panda = await PanDomainAuthentication.builder({
  cookieName: "gutoolsAuth-assym",
  region: "eu-west-1",
  bucket: "pan-domain-auth-settings",
  keyFile: "local.dev-gutools.co.uk.settings.public",
  validateUser: guardianValidation,
  credentialsProvider,
});

const app = new Hono();

// Health check – no auth required
app.get("/healthcheck", (c) => {
  return c.json({ status: "ok" });
});

// Page endpoint – can redirect for re-auth
app.get("/", async (c) => {
  const authResult: AuthenticationResult = await panda.verify(
    c.req.header("cookie"),
  );

  if (!authResult.success) {
    return c.text(`Authentication failed: ${authResult.reason}`, 401);
  }

  if (authResult.shouldRefreshCredentials) {
    return c.text("Session is stale – please re-authenticate.", 401);
  }

  const { user } = authResult;
  return c.html(
    `<h1>Success</h1>
    <p>Name: ${user.firstName} ${user.lastName}</p>
     <p>Email: ${user.email}</p>
     <p>Authenticated via: ${user.authenticatingSystem}</p>`,
  );
});

// API endpoint – cannot redirect, warns about stale credentials instead
app.get("/api/whoami", async (c) => {
  const authResult: AuthenticationResult = await panda.verify(
    c.req.header("cookie"),
  );

  if (!authResult.success) {
    return c.json({ error: authResult.reason }, 401);
  }

  const { user } = authResult;

  if (authResult.shouldRefreshCredentials) {
    const remaining = authResult.mustRefreshByEpochTimeMillis - Date.now();
    console.warn(`Stale Panda auth, will expire in ${remaining} milliseconds`);
    return c.json({ user, warning: "Session is stale, please refresh." });
  }

  return c.json({ user });
});

serve(
  {
    fetch: app.fetch,
    port: 3011,
  },
  (info) => {
    console.log(`Server is running on http://localhost:${info.port}`);
  },
);
