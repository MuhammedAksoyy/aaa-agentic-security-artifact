// Minimal external validator used to reproduce the D2 latency measurement (Section
// VI-D) and, informally, the B2 naive-substring baseline referenced in the paper.
// Not a security control -- it exists only so the retrofit's HTTP round trip
// (SecurityInterceptor.ts) has something to talk to during reproduction.
//
// Usage: node mock-validator.mjs   (listens on 127.0.0.1:8081)
import http from "node:http";

const PORT = 8081;

const server = http.createServer((req, res) => {
  if (req.method === "POST" && req.url === "/validate") {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
    });

    req.on("end", () => {
      try {
        const data = JSON.parse(body);
        let response;
        if (data.cmdText.includes("rm ")) {
          response = { status: "DENIED", reason: "Dangerous command (rm) is not allowed." };
        } else {
          response = { status: "APPROVED" };
        }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(response));
      } catch (e) {
        res.writeHead(400);
        res.end();
      }
    });
    return;
  }
  res.writeHead(404);
  res.end();
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`Mock validator listening on http://127.0.0.1:${PORT}`);
});
