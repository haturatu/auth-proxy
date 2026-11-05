"use strict";
(() => {
  const status = document.getElementById("status");
  const flow = new URLSearchParams(location.search).get("flow") || "";
  const decode = value => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
  const encode = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  async function request(path, data, method = "POST") {
    const response = await fetch(path, {method, credentials: "same-origin", headers: {"Content-Type": "application/json"}, ...(data === undefined ? {} : {body: JSON.stringify(data)})});
    if (!response.ok) throw new Error((await response.text()).trim() || "Request failed. Try again.");
    return response.status === 204 ? null : response.json();
  }
  function serialize(credential) {
    if (credential.toJSON) return credential.toJSON();
    const response = {};
    for (const name of ["clientDataJSON", "attestationObject", "authenticatorData", "signature", "userHandle"]) {
      if (credential.response[name]) response[name] = encode(credential.response[name]);
    }
    if (credential.response.getTransports) response.transports = credential.response.getTransports();
    return {id: credential.id, rawId: encode(credential.rawId), type: credential.type, authenticatorAttachment: credential.authenticatorAttachment, response, clientExtensionResults: credential.getClientExtensionResults()};
  }
  function options(json, registration) {
    if (registration && PublicKeyCredential.parseCreationOptionsFromJSON) return PublicKeyCredential.parseCreationOptionsFromJSON(json);
    if (!registration && PublicKeyCredential.parseRequestOptionsFromJSON) return PublicKeyCredential.parseRequestOptionsFromJSON(json);
    json.challenge = decode(json.challenge);
    if (json.user) json.user.id = decode(json.user.id);
    for (const key of ["allowCredentials", "excludeCredentials"]) for (const item of json[key] || []) item.id = decode(item.id);
    return json;
  }
  async function passkey(registration, username) {
    if (!window.PublicKeyCredential) throw new Error("This browser does not support passkeys. Use a password or a supported browser.");
    const action = registration ? "register" : "login";
    const begin = await request(`/webauthn/${action}/begin`, registration ? {username: username || ""} : {flow});
    const publicKey = options(begin.publicKey, registration);
    const credential = registration ? await navigator.credentials.create({publicKey}) : await navigator.credentials.get({publicKey});
    const result = await request(`/webauthn/${action}/finish`, serialize(credential));
    // A new account first establishes SSO; resume the original authorization
    // request through the normal login flow so its state remains intact.
    if (registration && flow) { location.assign(`/sso/login?flow=${encodeURIComponent(flow)}`); return; }
    location.assign(result.redirect);
  }
  async function run(button, action) {
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
    status.textContent = "Working…";
    try { await action(); }
    catch (error) { status.textContent = error.name === "NotAllowedError" ? "Passkey operation cancelled. You can try again." : error.message; }
    finally { button.disabled = false; button.removeAttribute("aria-busy"); }
  }
  const login = document.getElementById("passkey-login");
  if (login) login.addEventListener("click", () => run(login, () => passkey(false)));
  const add = document.getElementById("add-passkey");
  if (add) add.addEventListener("click", () => run(add, () => passkey(true)));
  const register = document.getElementById("passkey-register");
  if (register) register.addEventListener("submit", event => { event.preventDefault(); run(register.querySelector("button"), () => passkey(true, new FormData(register).get("username"))); });
  const password = document.getElementById("password-login");
  if (password) password.addEventListener("submit", event => {
    event.preventDefault();
    run(password.querySelector("button"), async () => {
      const data = Object.fromEntries(new FormData(password));
      const result = await request("/sso/password", {...data, flow});
      location.assign(result.redirect);
    });
  });
  const logout = document.getElementById("sso-logout");
  if (logout) logout.addEventListener("click", () => run(logout, async () => { await request("/sso/logout", {}); location.assign("/sso/login"); }));
  const list = document.getElementById("credentials");
  if (list) request("/webauthn/credentials", undefined, "GET").then(items => {
    if (!items.length) { list.textContent = "You have no passkeys yet."; return; }
    items.forEach((item, index) => {
      const row = document.createElement("li");
      const button = document.createElement("button");
      row.textContent = `Passkey ${index + 1} · Added ${new Date(item.created_at * 1000).toLocaleDateString()}`;
      button.type = "button";
      button.textContent = `Remove passkey ${index + 1}`;
      button.addEventListener("click", () => {
        if (!confirm("Remove this passkey and sign out of all applications?")) return;
        run(button, async () => { await request(`/webauthn/credentials/${encodeURIComponent(item.id)}`, undefined, "DELETE"); location.assign("/sso/login"); });
      });
      row.append(button); list.append(row);
    });
  }).catch(error => { status.textContent = error.message; });
})();
