const http = require("node:http");
const { timingSafeEqual } = require("node:crypto");
const { isIP } = require("node:net");

const apiKey = process.env.ESP32_API_KEY;
if (!apiKey) {
  console.error("ESP32_API_KEY must be set before starting the server.");
  process.exit(1);
}

const port = Number.parseInt(process.env.PORT || "3000", 10);
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  console.error("PORT must be an integer between 1 and 65535.");
  process.exit(1);
}

const maxBodyBytes = 16 * 1024;
let wifiConfig = null;
let wifiStatus = null;

function sendJson(res, statusCode, body) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  res.end(JSON.stringify(body));
}

function isAuthorized(req) {
  const match = /^Bearer\s+(\S+)$/i.exec(req.headers.authorization || "");
  if (!match) return false;

  const provided = Buffer.from(match[1]);
  const expected = Buffer.from(apiKey);
  return provided.length === expected.length && timingSafeEqual(provided, expected);
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let tooLarge = false;

    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > maxBodyBytes) {
        tooLarge = true;
        chunks.length = 0;
        return;
      }
      if (!tooLarge) chunks.push(chunk);
    });

    req.on("end", () => {
      if (tooLarge) {
        reject(Object.assign(new Error("Request body is too large."), { statusCode: 413 }));
        return;
      }

      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch {
        reject(Object.assign(new Error("Request body must be valid JSON."), { statusCode: 400 }));
      }
    });

    req.on("error", reject);
  });
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validateConfig(body) {
  if (!isRecord(body) || typeof body.ssid !== "string" || typeof body.password !== "string") {
    return "SSID and password must be strings.";
  }

  const ssidBytes = Buffer.byteLength(body.ssid, "utf8");
  if (ssidBytes < 1 || ssidBytes > 32 || body.ssid.includes("\0")) {
    return "SSID must be 1-32 UTF-8 bytes and must not contain a null character.";
  }

  const passwordBytes = Buffer.byteLength(body.password, "utf8");
  const isPassphrase = passwordBytes >= 8 && passwordBytes <= 63;
  const isRawPsk = passwordBytes === 64 && /^[\da-fA-F]{64}$/.test(body.password);
  if (!isPassphrase && !isRawPsk) {
    return "Password must be 8-63 UTF-8 bytes or a 64-character hexadecimal PSK.";
  }

  return null;
}

function validateStatus(body) {
  const allowedFields = new Set(["status", "ip", "rssi", "message"]);
  const statuses = new Set(["connecting", "connected", "disconnected", "error"]);
  if (!isRecord(body) || Object.keys(body).some((key) => !allowedFields.has(key))) {
    return "Status must be an object containing only status, ip, rssi, and message.";
  }
  if (!statuses.has(body.status)) {
    return "Status must be connecting, connected, disconnected, or error.";
  }
  if (body.ip !== undefined && (typeof body.ip !== "string" || !isIP(body.ip))) {
    return "IP must be a valid IPv4 or IPv6 address.";
  }
  if (body.rssi !== undefined &&
      (!Number.isInteger(body.rssi) || body.rssi < -127 || body.rssi > 0)) {
    return "RSSI must be an integer between -127 and 0.";
  }
  if (body.message !== undefined &&
      (typeof body.message !== "string" || Buffer.byteLength(body.message, "utf8") > 256)) {
    return "Message must be a string no longer than 256 UTF-8 bytes.";
  }

  return null;
}

const server = http.createServer(async (req, res) => {
  try {
    const pathname = new URL(req.url, "http://localhost").pathname;

    if (req.method === "GET" && pathname === "/health") {
      sendJson(res, 200, { status: "ok" });
      return;
    }

    if (!["/api/wifi/config", "/api/wifi/status"].includes(pathname)) {
      sendJson(res, 404, { error: "Not found." });
      return;
    }

    if (!isAuthorized(req)) {
      sendJson(res, 401, { error: "Unauthorized." });
      return;
    }

    if (pathname === "/api/wifi/config") {
      if (req.method === "GET") {
        if (!wifiConfig) {
          sendJson(res, 404, { error: "Wi-Fi configuration has not been set." });
          return;
        }
        sendJson(res, 200, wifiConfig);
        return;
      }

      if (req.method === "POST") {
        if (!req.headers["content-type"]?.toLowerCase().startsWith("application/json")) {
          sendJson(res, 415, { error: "Content-Type must be application/json." });
          return;
        }
        const body = await readJsonBody(req);
        const validationError = validateConfig(body);
        if (validationError) {
          sendJson(res, 400, { error: validationError });
          return;
        }
        wifiConfig = { ssid: body.ssid, password: body.password };
        sendJson(res, 200, { message: "Wi-Fi configuration saved." });
        return;
      }
    }

    if (pathname === "/api/wifi/status") {
      if (req.method === "GET") {
        sendJson(res, 200, wifiStatus || { status: "unknown" });
        return;
      }

      if (req.method === "POST") {
        if (!req.headers["content-type"]?.toLowerCase().startsWith("application/json")) {
          sendJson(res, 415, { error: "Content-Type must be application/json." });
          return;
        }
        const body = await readJsonBody(req);
        const validationError = validateStatus(body);
        if (validationError) {
          sendJson(res, 400, { error: validationError });
          return;
        }
        wifiStatus = { ...body, updatedAt: new Date().toISOString() };
        sendJson(res, 200, { message: "Wi-Fi status updated." });
        return;
      }
    }

    res.setHeader("Allow", "GET, POST");
    sendJson(res, 405, { error: "Method not allowed." });
  } catch (error) {
    const statusCode = Number.isInteger(error.statusCode) ? error.statusCode : 500;
    if (statusCode === 500) console.error("Request failed:", error);
    if (!res.headersSent) {
      sendJson(res, statusCode, {
        error: statusCode === 500 ? "Internal server error." : error.message,
      });
    } else {
      res.destroy();
    }
  }
});

server.on("clientError", (error, socket) => {
  console.error("HTTP client error:", error.message);
  if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
});

server.listen(port, "0.0.0.0", () => {
  console.log(`Wi-Fi config API listening on port ${port}`);
});