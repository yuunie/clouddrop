/**
 * CloudDrop - Durable Object for room management
 * Manages WebSocket connections and signaling for P2P file sharing
 * Supports optional password protection for secure rooms
 */

// WebSocket readyState constants (may not be available in Workers environment)
const WS_READY_STATE = {
  CONNECTING: 0,
  OPEN: 1,
  CLOSING: 2,
  CLOSED: 3,
};

export interface Env {
  ROOM: DurableObjectNamespace;
}

interface Peer {
  id: string;
  name: string;
  deviceType: 'desktop' | 'mobile' | 'tablet';
  browserInfo?: string;
  webSocket: WebSocket;
}

interface SignalingMessage {
  type: 'join' | 'leave' | 'offer' | 'answer' | 'ice-candidate' | 'peers' | 'text' | 'peer-joined' | 'peer-left' | 'relay-data' | 'name-changed' | 'key-exchange' | 'file-request' | 'file-response' | 'file-cancel';
  from?: string;
  to?: string;
  data?: unknown;
}

/**
 * Peer attachment data stored with WebSocket (survives hibernation)
 */
interface PeerAttachment {
  id: string;
  name: string;
  deviceType: 'desktop' | 'mobile' | 'tablet';
  browserInfo?: string;
  publicKey?: string;
}

/**
 * Room Durable Object - handles WebSocket connections for a room (based on IP)
 * Uses WebSocket Hibernation API for cost efficiency
 * Peer data is stored in WebSocket attachments to survive hibernation
 * Supports optional password protection for secure rooms
 */
export class Room {
  private state: DurableObjectState;
  private passwordHash: string | null; // Password hash for secure rooms (null = no password)

  constructor(state: DurableObjectState, _env: Env) {
    this.state = state;
    this.passwordHash = null;

    // Load password hash from storage on initialization
    this.state.blockConcurrencyWhile(async () => {
      this.passwordHash = await this.state.storage.get<string>('passwordHash') || null;
    });
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/ws') {
      return this.handleWebSocket(request);
    }

    if (url.pathname === '/set-password') {
      // Set room password (only if not already set)
      return this.handleSetPassword(request);
    }

    if (url.pathname === '/check-password') {
      // Check if room has password protection
      return this.handleCheckPassword(request);
    }

    return new Response('Not Found', { status: 404 });
  }

  /**
   * Check if room requires password
   */
  private handleCheckPassword(_request: Request): Response {
    return new Response(JSON.stringify({
      hasPassword: this.passwordHash !== null
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  /**
   * Set room password (only if not already set)
   * This is called by the first user who creates the room with a password
   */
  private async handleSetPassword(request: Request): Promise<Response> {
    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    // Only allow setting password if it's not already set
    if (this.passwordHash !== null) {
      return new Response(JSON.stringify({
        success: false,
        error: 'Password already set for this room'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    try {
      const body = await request.json() as { passwordHash: string };

      if (!body.passwordHash || typeof body.passwordHash !== 'string') {
        return new Response(JSON.stringify({
          success: false,
          error: 'Invalid password hash'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      // Store password hash
      this.passwordHash = body.passwordHash;
      await this.state.storage.put('passwordHash', body.passwordHash);

      return new Response(JSON.stringify({
        success: true
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      return new Response(JSON.stringify({
        success: false,
        error: 'Invalid request body'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }

  private handleWebSocket(request: Request): Response {
    // Check for WebSocket upgrade
    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader !== 'websocket') {
      return new Response('Expected WebSocket', { status: 426 });
    }

    // Get room code from header (passed by index.ts)
    const roomCode = request.headers.get('X-Room-Code') || '';

    // Get password hash (will be verified after connection is established)
    const providedPasswordHash = request.headers.get('X-Room-Password-Hash');

    // Create WebSocket pair
    const pair = new WebSocketPair();
    const [client, server] = [pair[0], pair[1]];

    // Accept the WebSocket with hibernation API
    // Use tag to store room code (survives hibernation)
    this.state.acceptWebSocket(server, [roomCode]);

    // If room is password-protected, verify immediately after accept
    if (this.passwordHash !== null) {
      if (!providedPasswordHash) {
        // Send error message then close
        server.send(JSON.stringify({
          type: 'error',
          error: 'PASSWORD_REQUIRED',
          message: '此房间需要密码'
        }));
        server.close(4001, 'PASSWORD_REQUIRED');
        return new Response(null, { status: 101, webSocket: client });
      }

      if (providedPasswordHash !== this.passwordHash) {
        // Send error message then close
        server.send(JSON.stringify({
          type: 'error',
          error: 'PASSWORD_INCORRECT',
          message: '密码错误'
        }));
        server.close(4002, 'PASSWORD_INCORRECT');
        return new Response(null, { status: 101, webSocket: client });
      }
    }

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  }

  /**
   * Get all active peers from WebSocket attachments (survives hibernation)
   * Only returns peers with OPEN WebSocket connections
   */
  private getActivePeers(): Map<string, { ws: WebSocket; attachment: PeerAttachment }> {
    const peers = new Map<string, { ws: WebSocket; attachment: PeerAttachment }>();
    const webSockets = this.state.getWebSockets();

    for (const ws of webSockets) {
      const attachment = ws.deserializeAttachment() as PeerAttachment | null;
      const readyState = ws.readyState;

      // Only include WebSockets that are OPEN (readyState === 1) and have valid attachment
      // Use explicit constant as WebSocket.OPEN may not be available in Workers
      if (attachment && attachment.id && readyState === WS_READY_STATE.OPEN) {
        peers.set(attachment.id, { ws, attachment });
      }
    }

    return peers;
  }

  /**
   * Get peer ID from WebSocket attachment
   */
  private getPeerIdFromWs(ws: WebSocket): string | undefined {
    const attachment = ws.deserializeAttachment() as PeerAttachment | null;
    return attachment?.id;
  }

  /**
   * WebSocket message handler (Hibernation API)
   */
  async webSocketMessage(ws: WebSocket, message: ArrayBuffer | string): Promise<void> {
    try {
      const data = typeof message === 'string' ? message : new TextDecoder().decode(message);
      const msg: SignalingMessage = JSON.parse(data);

      switch (msg.type) {
        case 'join':
          await this.handleJoin(ws, msg);
          break;
        case 'offer':
        case 'answer':
        case 'ice-candidate':
          await this.handleSignaling(ws, msg);
          break;
        case 'text':
          await this.handleText(ws, msg);
          break;
        case 'relay-data':
          await this.handleRelayData(ws, msg);
          break;
        case 'key-exchange':
          await this.handleKeyExchange(ws, msg);
          break;
        case 'name-changed':
          await this.handleNameChanged(ws, msg);
          break;
        case 'file-request':
        case 'file-response':
        case 'file-cancel':
          await this.handleFileSignaling(ws, msg);
          break;
      }
    } catch (error) {
      console.error('WebSocket message error:', error);
    }
  }

  /**
   * WebSocket close handler (Hibernation API)
   */
  async webSocketClose(ws: WebSocket, _code: number, _reason: string, _wasClean: boolean): Promise<void> {
    await this.handleLeave(ws);
  }

  /**
   * WebSocket error handler (Hibernation API)
   */
  async webSocketError(ws: WebSocket, _error: unknown): Promise<void> {
    await this.handleLeave(ws);
  }

  /**
   * Handle peer joining the room
   */
  private async handleJoin(ws: WebSocket, msg: SignalingMessage): Promise<void> {
    const joinData = msg.data as { name: string; deviceType: 'desktop' | 'mobile' | 'tablet'; browserInfo?: string };
    const peerId = crypto.randomUUID();

    // Get room code from WebSocket tag
    const tags = this.state.getTags(ws);
    const roomCode = tags.length > 0 ? tags[0] : '';

    // Create peer attachment data
    const attachment: PeerAttachment = {
      id: peerId,
      name: joinData.name || this.generateName(),
      deviceType: joinData.deviceType || 'desktop',
      browserInfo: joinData.browserInfo,
    };

    // Store peer info in WebSocket attachment (survives hibernation)
    ws.serializeAttachment(attachment);

    // Setup auto-response for ping/pong
    this.state.setWebSocketAutoResponse(new WebSocketRequestResponsePair('ping', 'pong'));

    // Get all other active peers from their WebSocket attachments
    const activePeers = this.getActivePeers();

    const otherPeers = Array.from(activePeers.entries())
      .filter(([id]) => id !== peerId)
      .map(([id, { attachment: p }]) => ({ id, name: p.name, deviceType: p.deviceType, browserInfo: p.browserInfo }));

    // Send peer their ID, room code, and list of other peers
    ws.send(JSON.stringify({
      type: 'joined',
      peerId,
      roomCode,
      peers: otherPeers,
    }));

    // Notify other peers about new peer
    this.broadcast({
      type: 'peer-joined',
      data: { id: peerId, name: attachment.name, deviceType: attachment.deviceType, browserInfo: attachment.browserInfo },
    }, peerId);
  }

  /**
   * Handle peer leaving the room
   */
  private async handleLeave(ws: WebSocket): Promise<void> {
    const peerId = this.getPeerIdFromWs(ws);
    
    if (peerId) {
      // Notify other peers
      this.broadcast({
        type: 'peer-left',
        data: { id: peerId },
      });
    }
  }

  /**
   * Handle WebRTC signaling messages (offer/answer/ice-candidate)
   */
  private async handleSignaling(ws: WebSocket, msg: SignalingMessage): Promise<void> {
    if (!msg.to) return;

    const fromPeerId = this.getPeerIdFromWs(ws);
    if (!fromPeerId) return;

    // Find target peer - iterate through all WebSockets
    const webSockets = this.state.getWebSockets();
    for (const targetWs of webSockets) {
      try {
        const attachment = targetWs.deserializeAttachment() as PeerAttachment | null;
        if (attachment && attachment.id === msg.to) {
          targetWs.send(JSON.stringify({
            type: msg.type,
            from: fromPeerId,
            data: msg.data,
          }));
          break;
        }
      } catch (e) {
        console.error(`[Room] Failed to send signaling to ${msg.to}:`, e);
      }
    }
  }

  /**
   * Handle text messages between peers
   */
  private async handleText(ws: WebSocket, msg: SignalingMessage): Promise<void> {
    if (!msg.to) return;

    const fromPeerId = this.getPeerIdFromWs(ws);
    if (!fromPeerId) return;

    this.sendToPeer(msg.to, {
      type: 'text',
      from: fromPeerId,
      data: msg.data,
    });
  }

  /**
   * Handle relay data messages (fallback when P2P fails)
   * Forwards binary data chunks between peers via WebSocket
   */
  private async handleRelayData(ws: WebSocket, msg: SignalingMessage): Promise<void> {
    if (!msg.to) return;

    const fromPeerId = this.getPeerIdFromWs(ws);
    if (!fromPeerId) return;

    this.sendToPeer(msg.to, {
      type: 'relay-data',
      from: fromPeerId,
      data: msg.data,
    });
  }

  /**
   * Handle key exchange messages (for relay mode encryption)
   */
  private async handleKeyExchange(ws: WebSocket, msg: SignalingMessage): Promise<void> {
    if (!msg.to) return;

    const fromPeerId = this.getPeerIdFromWs(ws);
    if (!fromPeerId) return;

    this.sendToPeer(msg.to, {
      type: 'key-exchange',
      from: fromPeerId,
      data: msg.data,
    });
  }

  /**
   * Handle file request/response signaling messages
   * Used for file transfer confirmation flow
   */
  private async handleFileSignaling(ws: WebSocket, msg: SignalingMessage): Promise<void> {
    if (!msg.to) return;

    const fromPeerId = this.getPeerIdFromWs(ws);
    if (!fromPeerId) return;

    this.sendToPeer(msg.to, {
      type: msg.type, // 'file-request' or 'file-response' or 'file-cancel'
      from: fromPeerId,
      data: msg.data,
    });
  }

  /**
   * Send message to a specific peer by ID
   * Iterates through all WebSockets to find the target
   */
  private sendToPeer(targetPeerId: string, message: object): boolean {
    const webSockets = this.state.getWebSockets();

    for (const ws of webSockets) {
      try {
        const attachment = ws.deserializeAttachment() as PeerAttachment | null;
        if (attachment && attachment.id === targetPeerId) {
          ws.send(JSON.stringify(message));
          return true;
        }
      } catch (e) {
        console.error(`[Room] Failed to send to ${targetPeerId}:`, e);
      }
    }

    return false;
  }

  /**
   * Broadcast message to all peers except excluded one
   * Uses direct WebSocket iteration with try-catch for robustness
   */
  private broadcast(msg: SignalingMessage, excludePeerId?: string): void {
    const message = JSON.stringify(msg);
    const webSockets = this.state.getWebSockets();

    for (const ws of webSockets) {
      try {
        const attachment = ws.deserializeAttachment() as PeerAttachment | null;

        // Skip if no attachment, no ID, or is the excluded peer
        if (!attachment || !attachment.id || attachment.id === excludePeerId) {
          continue;
        }

        // Try to send regardless of readyState - let the send fail if connection is bad
        ws.send(message);
      } catch (e) {
        // Silently ignore send failures - peer may have disconnected
      }
    }
  }

  /**
   * Generate a random device name
   */
  private generateName(): string {
    const adjectives = ['Swift', 'Bright', 'Cool', 'Fast', 'Sleek', 'Sharp', 'Bold', 'Calm'];
    const nouns = ['Phoenix', 'Dragon', 'Falcon', 'Tiger', 'Eagle', 'Panda', 'Wolf', 'Lion'];
    const adj = adjectives[Math.floor(Math.random() * adjectives.length)];
    const noun = nouns[Math.floor(Math.random() * nouns.length)];
    return `${adj} ${noun}`;
  }

  /**
   * Handle peer name change
   */
  private async handleNameChanged(ws: WebSocket, msg: SignalingMessage): Promise<void> {
    const senderId = (ws.deserializeAttachment() as PeerAttachment | null)?.id;
    if (!senderId) return;

    const nameData = msg.data as { name: string };
    
    // Update peer attachment with new name
    const attachment = ws.deserializeAttachment() as PeerAttachment | null;
    if (attachment) {
      attachment.name = nameData.name;
      ws.serializeAttachment(attachment);
    }

    // Broadcast name change to all other peers
    this.broadcast({
      type: 'name-changed',
      from: senderId,
      data: { name: nameData.name }
    }, senderId);
  }
}
