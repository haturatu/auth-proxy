import assert from "node:assert/strict";
import { createServer } from "node:http";
import { request as httpsRequest } from "node:https";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { chromium } from "playwright";

const auth = "https://auth.example.test:18443";
const appA = "https://app-a.example.test:18443";
const appB = "https://app-b.other.test:18443";
const cookieHeader = cookies => cookies.map(c => `${c.name}=${c.value}`).join("; ");

function raw(origin, path, {method = "GET", headers = {}, body} = {}) {
  const url = new URL(origin);
  return new Promise((resolve, reject) => {
    const req = httpsRequest({hostname: "127.0.0.1", port: url.port, servername: url.hostname, rejectUnauthorized: false, path, method, headers: {Host: url.host, ...headers}}, res => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", chunk => data += chunk);
      res.on("end", () => resolve({status: res.statusCode, headers: res.headers, body: data}));
    });
    req.on("error", reject);
    req.end(body);
  });
}

const servers = [];
for (const [app, port] of [["app-a", 18081], ["app-b", 18082]]) {
  const server = createServer((req, res) => {
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({app, method: req.method, headers: req.headers}));
  });
  server.on("upgrade", (req, socket) => {
    const accept = createHash("sha1").update(req.headers["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    socket.on("data", () => socket.end());
    socket.on("error", () => {});
  });
  await new Promise(resolve => server.listen(port, "127.0.0.1", resolve));
  servers.push(server);
}

const browser = await chromium.launch({
  executablePath: process.env.CHROMIUM_PATH || undefined,
  args: ["--no-proxy-server", "--host-resolver-rules=MAP auth.example.test 127.0.0.1, MAP app-a.example.test 127.0.0.1, MAP app-b.other.test 127.0.0.1"],
});

async function device(credentials = []) {
  const context = await browser.newContext({ignoreHTTPSErrors: true});
  const page = await context.newPage();
  page.setDefaultTimeout(15000);
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const {authenticatorId} = await cdp.send("WebAuthn.addVirtualAuthenticator", {options: {protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true}});
  for (const credential of credentials) await cdp.send("WebAuthn.addCredential", {authenticatorId, credential});
  return {context, page, cdp, authenticatorId};
}

async function passkeyLogin(device, origin = appA) {
  await device.page.goto(origin + "/");
  await device.page.waitForURL(auth + "/sso/login**");
  await device.page.getByRole("button", {name: "Sign in with a passkey", exact: true}).click();
  await device.page.waitForURL(origin + "/");
}

try {
  assert.equal((await raw(auth, "/internal/authz")).status, 404);
  assert.equal((await raw(auth, "/gateway/start")).status, 404);
  assert.equal((await raw(appA, "/_auth/check")).status, 404);
  const api = await raw(appA, "/api/items", {headers: {Accept: "application/json"}});
  assert.equal(api.status, 401);
  assert.equal(api.headers.location, undefined);
  assert.equal((await raw(appA,"/api/items",{headers:{Accept:"text/html","Sec-Fetch-Mode":"navigate","Sec-Fetch-Dest":"document"}})).status,401);
  const unauthPost = await raw(appA, "/api/items", {method: "POST", headers: {Origin: appA, Accept: "text/html", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}, body: "never-replayed"});
  assert.equal(unauthPost.status, 401);
  assert.equal(unauthPost.headers.location, undefined);
  console.log("PASS: private routes and API/POST redirect policy");

  const one = await device();
  let registrationRequest;
  one.page.on("request", async req => {
    if (req.url() === auth+"/webauthn/register/finish" && !registrationRequest) {
      registrationRequest = {body:req.postData(), headers:await req.allHeaders()};
    }
  });
  await one.page.goto(appA + "/deep/link?q=hello");
  await one.page.waitForURL(auth + "/sso/login**");
  if (process.env.SSO_TEST_OUTPUT) {
    await mkdir(process.env.SSO_TEST_OUTPUT,{recursive:true});
    await one.page.screenshot({path:join(process.env.SSO_TEST_OUTPUT,"login-desktop.png"),fullPage:true});
    await one.page.setViewportSize({width:390,height:844});
    await one.page.screenshot({path:join(process.env.SSO_TEST_OUTPUT,"login-mobile.png"),fullPage:true});
    await one.page.setViewportSize({width:1280,height:800});
  }
  await one.page.getByText("Create an account with a passkey", {exact: true}).click();
  const username = `passkey-user-${Date.now()}`;
  await one.page.getByLabel("Username", {exact: true}).last().fill(username);
  await one.page.getByRole("button", {name: "Create account with a passkey", exact: true}).click();
  await one.page.waitForURL(appA + "/deep/link?q=hello");
  const identity = JSON.parse(await one.page.locator("body").innerText());
  assert.equal(identity.headers["x-auth-request-user"], username);
  assert.equal(identity.headers["x-auth-request-role"], "user");
  assert.equal(identity.headers.cookie, undefined);
  assert.equal((await raw(auth,"/webauthn/register/finish",{method:"POST",body:registrationRequest.body,headers:{Cookie:registrationRequest.headers.cookie,Origin:auth,"Content-Type":"application/json"}})).status,400);
  console.log("PASS: real WebAuthn registration and OIDC callback across Nginx");

  // The example restricts app-b to admins. Role changes apply immediately.
  assert.equal((await one.page.goto(appB + "/")).status(), 403);
  execFileSync("python3", ["-c", "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('UPDATE users SET role=? WHERE username=?',('admin',sys.argv[2])); c.commit()", process.env.SSO_TEST_DB, username]);
  await one.page.goto(appB + "/");
  await one.page.waitForURL(appB + "/");
  assert.equal(JSON.parse(await one.page.locator("body").innerText()).headers["x-auth-request-user"], username);
  const cookies = await one.context.cookies();
  const sso = cookies.filter(c => c.name === "__Host-sso_session");
  const apps = cookies.filter(c => c.name === "__Host-app_session");
  assert.equal(sso.length, 1);
  assert.equal(sso[0].domain, "auth.example.test");
  assert.deepEqual(apps.map(c => c.domain).sort(), ["app-a.example.test", "app-b.other.test"]);
  for (const cookie of [...sso, ...apps]) { assert.ok(cookie.secure && cookie.httpOnly); assert.equal(cookie.sameSite, "Lax"); assert.equal(cookie.path, "/"); }
  console.log("PASS: SSO across unrelated parent domains, host-only cookies and roles");

  const exported = await one.cdp.send("WebAuthn.getCredentials", {authenticatorId: one.authenticatorId});
  const two = await device(exported.credentials);
  await passkeyLogin(two);
  await one.page.goto(appA + "/");
  assert.equal(JSON.parse(await one.page.locator("body").innerText()).app, "app-a");
  console.log("PASS: real passkey login on another device preserves existing sessions");

  await one.context.addCookies([{url: appA, name: "application", value: "retained"}]);
  const aCookies = cookieHeader(await one.context.cookies(appA));
  const forwarded = await raw(appA, "/identity", {headers: {Cookie: aCookies, "X-Auth-Request-User": "attacker", "X-Auth-Request-Role": "attacker", "X-Auth-Request-JWT": "attacker", Authorization: "Bearer attacker"}});
  assert.equal(forwarded.status, 200);
  const upstream = JSON.parse(forwarded.body).headers;
  assert.equal(upstream["x-auth-request-user"], username);
  assert.equal(upstream["x-auth-request-role"], "admin");
  assert.equal(upstream["x-auth-request-jwt"], undefined);
  assert.equal(upstream.authorization, undefined);
  assert.equal(upstream.cookie, "application=retained");
  // Several application cookies can exceed Nginx's default upstream response
  // header buffer. The auth subrequest must preserve them without a 502.
  const large = await raw(appA,"/identity",{headers:{Cookie:aCookies+"; large_a="+"a".repeat(2500)+"; large_b="+"b".repeat(2500)}});
  assert.equal(large.status,200);
  assert.ok(JSON.parse(large.body).headers.cookie.includes("large_b="));
  assert.ok(!JSON.parse(large.body).headers.cookie.includes("__Host-"));
  const post = await raw(appA, "/change", {method: "POST", headers: {Cookie: aCookies, Origin: appA}, body: "preserve-method"});
  assert.equal(post.status, 200);
  assert.equal(JSON.parse(post.body).method, "POST");
  assert.equal((await raw(appA, "/change", {method: "POST", headers: {Cookie: aCookies, Origin: appB}})).status, 403);
  const socketOK = await one.page.evaluate(url => new Promise(resolve => { const ws = new WebSocket(url); ws.onopen = () => { ws.close(); resolve(true); }; ws.onerror = () => resolve(false); }), appA.replace("https:", "wss:") + "/socket");
  assert.equal(socketOK, true);
  assert.equal((await raw(appA, "/socket", {headers: {Cookie: aCookies, Connection: "Upgrade", Upgrade: "websocket", "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Version": "13", Origin: appB}})).status, 403);
  console.log("PASS: identity spoofing, credential filtering, POST and WebSocket Origin checks");

  const localLogout = await one.page.evaluate(async () => (await fetch("/_auth/logout", {method: "POST"})).status);
  assert.equal(localLogout, 204);
  assert.equal((await one.context.cookies(appA)).some(c => c.name === "__Host-app_session"), false);
  assert.equal((await raw(appB, "/", {headers: {Cookie: cookieHeader(await one.context.cookies(appB))}})).status, 200);
  await one.page.goto(appA + "/"); // Existing SSO silently issues a new app session.
  await one.page.waitForURL(appA + "/");
  console.log("PASS: app logout leaves the other app and SSO intact");

  await one.page.goto(auth + "/sso/account");
  await one.page.getByRole("button", {name: "Sign out of all applications on this device"}).click();
  await one.page.waitForURL(auth + "/sso/login");
  assert.equal((await raw(appA, "/", {headers: {Cookie: aCookies}})).status, 401);
  assert.equal((await raw(appB, "/", {headers: {Cookie: cookieHeader(await one.context.cookies(appB))}})).status, 401);
  assert.equal((await raw(appA, "/", {headers: {Cookie: cookieHeader(await two.context.cookies(appA))}})).status, 200);
  console.log("PASS: SSO logout revokes all linked app sessions and preserves another device");

  // Feed a correctly shaped assertion with a bogus cryptographic signature.
  await one.cdp.send("WebAuthn.setResponseOverrideBits", {authenticatorId: one.authenticatorId, isBogusSignature: true});
  await one.page.getByRole("button", {name: "Sign in with a passkey", exact: true}).click();
  await one.page.getByRole("status").filter({hasText: "Passkey verification failed"}).waitFor();
  await one.cdp.send("WebAuthn.setResponseOverrideBits", {authenticatorId: one.authenticatorId, isBogusSignature: false});
  // Alter the signed client data to an unregistered origin.
  await one.page.route("**/webauthn/login/finish", async route => {
    const payload = route.request().postDataJSON();
    const clientData = JSON.parse(Buffer.from(payload.response.clientDataJSON, "base64url").toString());
    clientData.origin = appA;
    payload.response.clientDataJSON = Buffer.from(JSON.stringify(clientData)).toString("base64url");
    await route.continue({postData: JSON.stringify(payload)});
  }, {times: 1});
  let failed = one.page.waitForResponse(response => response.url() === auth+"/webauthn/login/finish");
  await one.page.getByRole("button", {name: "Sign in with a passkey", exact: true}).click();
  assert.equal((await failed).status(),401);
  await one.page.getByRole("button", {name: "Sign in with a passkey", exact: true}).waitFor({state:"visible"});
  await one.page.route("**/webauthn/login/finish", async route => {
    const payload = route.request().postDataJSON();
    const clientData = JSON.parse(Buffer.from(payload.response.clientDataJSON,"base64url").toString());
    clientData.challenge = Buffer.from("a-different-challenge").toString("base64url");
    payload.response.clientDataJSON = Buffer.from(JSON.stringify(clientData)).toString("base64url");
    await route.continue({postData:JSON.stringify(payload)});
  },{times:1});
  failed = one.page.waitForResponse(response => response.url() === auth+"/webauthn/login/finish");
  await one.page.getByRole("button", {name: "Sign in with a passkey", exact: true}).click();
  assert.equal((await failed).status(),401);
  console.log("PASS: WebAuthn replay, invalid signatures, origins and challenges rejected");

  // Synchronize the authenticator's counter after device two's assertion.
  await one.cdp.send("WebAuthn.clearCredentials", {authenticatorId: one.authenticatorId});
  const updated = await two.cdp.send("WebAuthn.getCredentials", {authenticatorId: two.authenticatorId});
  for (const credential of updated.credentials) await one.cdp.send("WebAuthn.addCredential", {authenticatorId: one.authenticatorId, credential});
  await one.page.goto(auth + "/sso/login");
  await one.page.getByRole("button", {name: "Sign in with a passkey", exact: true}).click();
  await one.page.waitForURL(auth + "/sso/account");
  const lastKey = await one.page.evaluate(async () => {
    const credentials = await (await fetch("/webauthn/credentials")).json();
    return (await fetch(`/webauthn/credentials/${encodeURIComponent(credentials[0].id)}`, {method: "DELETE"})).status;
  });
  assert.equal(lastKey, 409);
  // A second key is a separate authenticator. An exclusion list correctly
  // prevents creating a duplicate on the first authenticator.
  await one.cdp.send("WebAuthn.removeVirtualAuthenticator", {authenticatorId: one.authenticatorId});
  const secondKey = await one.cdp.send("WebAuthn.addVirtualAuthenticator", {options: {protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true}});
  one.authenticatorId = secondKey.authenticatorId;
  await one.page.getByRole("button", {name: "Add a passkey", exact: true}).click();
  await one.page.getByRole("button", {name: "Remove passkey 2"}).waitFor();
  if (process.env.SSO_TEST_OUTPUT) await one.page.screenshot({path:join(process.env.SSO_TEST_OUTPUT,"account-desktop.png"),fullPage:true});
  assert.equal((await raw(appA, "/", {headers: {Cookie: cookieHeader(await two.context.cookies(appA))}})).status, 401);
  one.page.once("dialog", dialog => dialog.accept());
  await one.page.getByRole("button", {name: "Remove passkey 1"}).click();
  await one.page.waitForURL(auth + "/sso/login");
  console.log("PASS: passkey add/delete revokes sessions and last-credential removal is blocked");
} finally {
  await browser.close();
  for (const server of servers) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
}
