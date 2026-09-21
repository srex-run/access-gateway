export class TransportError extends Error {}
export function requiresEncryption(method: string, path: string): boolean
export function encryptedFetch(url: string, options?: RequestInit): Promise<Response>
export function sealTerminalStart(path: string, body: unknown, signal?: AbortSignal): Promise<{ challenge_id: string; envelope: { version: number; kid: string; encrypted_key: string; nonce: string; ciphertext: string } }>
