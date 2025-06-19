import express from "express";
import http from "http";
import path from "path";
import { WebSocketServer, WebSocket } from "ws";

// Create Express app and HTTP server
const app = express();
const server = http.createServer(app);

// Set up WebSocket server
const wss = new WebSocketServer({ server });

// Represents a connected client session
type Client = {
  id: string;
  socket: WebSocket;
  publicKey?: string;
};

// Message types received from clients
type IncomingMessage =
  | { type: "publicKey"; key: string }
  | { type: "getPublicKey"; for: string }
  | {
      type: "message";
      to: string;
      ciphertext: { iv: number[]; data: number[] };
    };

// Message types sent to clients
type OutgoingMessage =
  | { type: "init"; sessionId: string }
  | { type: "publicKey"; for: string; key: string }
  | {
      type: "message";
      from: string;
      ciphertext: { iv: number[]; data: number[] };
      senderPublicKey?: string;
    };

// Map of session IDs to clients
const clients = new Map<string, Client>();

// Generates a random 6-digit session ID
function generateSessionId(): string {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Handle new WebSocket connection
wss.on("connection", (ws: WebSocket) => {
  const sessionId = generateSessionId();

  // Store client
  clients.set(sessionId, { id: sessionId, socket: ws });

  // Send session ID to client
  const initMsg: OutgoingMessage = { type: "init", sessionId };
  ws.send(JSON.stringify(initMsg));

  // Handle incoming messages
  ws.on("message", (data: string | Buffer) => {
    try {
      const parsed = JSON.parse(data.toString()) as IncomingMessage;

      switch (parsed.type) {
        case "publicKey":
          // Store client's public key
          clients.get(sessionId)!.publicKey = parsed.key;
          break;

        case "getPublicKey": {
          // Send requested public key to requester
          const recipient = clients.get(parsed.for);
          if (recipient?.publicKey) {
            const reply: OutgoingMessage = {
              type: "publicKey",
              for: parsed.for,
              key: recipient.publicKey,
            };
            ws.send(JSON.stringify(reply));
          }
          break;
        }

        case "message": {
          const recipient = clients.get(parsed.to);
          if (recipient) {
            const senderPublicKey = clients.get(sessionId)?.publicKey;
            const forward: OutgoingMessage = {
              type: "message",
              from: sessionId,
              ciphertext: parsed.ciphertext,
              senderPublicKey,
            };
            recipient.socket.send(JSON.stringify(forward));
          }
          break;
        }

        default:
          console.warn("Unknown message type");
      }
    } catch (err) {
      console.error("Error parsing message:", err);
    }
  });

  // Remove client when disconnected
  ws.on("close", () => {
    clients.delete(sessionId);
  });
});

// Serve static frontend files
const publicPath = path.join(__dirname, "public");
app.use(express.static(publicPath));

// Start the HTTP and WebSocket server
server.listen(3000, () => console.log("Listening on http://localhost:3000"));
