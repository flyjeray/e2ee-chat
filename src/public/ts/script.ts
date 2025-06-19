const ws = new WebSocket(`ws://${location.host}`);

let sessionId: string | null = null;
let myECDHKeyPair: CryptoKeyPair | null = null;

type ChatMessage =
  | { type: "init"; sessionId: string }
  | { type: "publicKey"; for: string; key: string }
  | {
      type: "message";
      from: string;
      ciphertext: { iv: number[]; data: number[] };
      senderPublicKey: string;
    };

// Map of known peers with their public and derived AES keys
const peers = new Map<string, { publicKey: CryptoKey; sharedKey: CryptoKey }>();

// DOM elements
const myIdText = document.getElementById("myId") as HTMLSpanElement;
const sendButton = document.getElementById(
  "sendBtn"
) as HTMLButtonElement | null;
const recipientInput = document.getElementById(
  "recipientId"
) as HTMLInputElement;
const messageInput = document.getElementById("message") as HTMLInputElement;
const messages = document.getElementById("messages") as HTMLUListElement | null;

// Generate an ephemeral ECDH key pair
async function generateECDHKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey"]
  );
}

// Export a public key to base64-encoded string
async function exportPublicKey(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey("raw", key);
  return btoa(String.fromCharCode(...new Uint8Array(raw)));
}

// Import a public key from a base64 string
async function importPublicKey(base64Key: string): Promise<CryptoKey> {
  const binary = Uint8Array.from(atob(base64Key), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey(
    "raw",
    binary.buffer,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );
}

// Derive a shared AES key from your private key and peer's public key
async function deriveSharedKey(
  privateKey: CryptoKey,
  publicKey: CryptoKey
): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    { name: "ECDH", public: publicKey },
    privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// Encrypt plaintext with a shared AES key
async function encryptWithKey(
  key: CryptoKey,
  plaintext: string
): Promise<{ iv: number[]; data: number[] }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoded
  );
  return {
    iv: Array.from(iv),
    data: Array.from(new Uint8Array(ciphertext)),
  };
}

// Decrypt a message using a shared AES key
async function decryptWithKey(
  key: CryptoKey,
  encrypted: { iv: number[]; data: number[] }
): Promise<string> {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(encrypted.iv) },
    key,
    new Uint8Array(encrypted.data)
  );
  return new TextDecoder().decode(plaintext);
}

// Handle messages from the WebSocket server
ws.onmessage = async (event: MessageEvent) => {
  const msg = JSON.parse(event.data) as ChatMessage;

  if (msg.type === "init") {
    // Received session ID; generate and send our public key
    sessionId = msg.sessionId;
    myIdText.textContent = sessionId;

    myECDHKeyPair = await generateECDHKeyPair();
    const pubKey = await exportPublicKey(myECDHKeyPair.publicKey);
    ws.send(JSON.stringify({ type: "publicKey", key: pubKey }));
  }

  if (msg.type === "publicKey" && myECDHKeyPair) {
    // Received peer's public key; derive shared AES key
    const peerId = msg.for;
    const pubKey = await importPublicKey(msg.key);
    const sharedKey = await deriveSharedKey(myECDHKeyPair.privateKey, pubKey);
    peers.set(peerId, { publicKey: pubKey, sharedKey });
    sendMessage(peerId); // Send message if one is queued
  }

  if (msg.type === "message") {
    const senderId = msg.from;

    // If sender is not known yet, derive key from provided public key
    if (!peers.has(senderId) && myECDHKeyPair) {
      const pubKey = await importPublicKey(msg.senderPublicKey);
      const sharedKey = await deriveSharedKey(myECDHKeyPair.privateKey, pubKey);
      peers.set(senderId, { publicKey: pubKey, sharedKey });
    }

    // Decrypt and display the message
    const plaintext = await decryptWithKey(
      peers.get(senderId)!.sharedKey,
      msg.ciphertext
    );
    const li = document.createElement("li");
    li.textContent = `[${senderId}]: ${plaintext}`;
    messages?.appendChild(li);
  }
};

// Encrypt and send a message to a known peer
async function sendMessage(recipientId: string): Promise<void> {
  const msg = messageInput?.value;
  const peer = peers.get(recipientId);
  if (!peer || !msg) return;

  const encrypted = await encryptWithKey(peer.sharedKey, msg);
  ws.send(
    JSON.stringify({
      type: "message",
      to: recipientId,
      ciphertext: encrypted,
    })
  );

  const li = document.createElement("li");
  li.textContent = `To [${recipientId}]: ${msg}`;
  messages?.appendChild(li);
}

// Send public key request or send encrypted message if peer is known
sendButton?.addEventListener("click", () => {
  const recipientId = recipientInput?.value.trim();
  if (!recipientId) return;

  if (!peers.has(recipientId)) {
    ws.send(JSON.stringify({ type: "getPublicKey", for: recipientId }));
  } else {
    sendMessage(recipientId);
  }
});
