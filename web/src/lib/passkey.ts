import type { PasskeyAssertion, PasskeyOptions, PasskeyRegistration } from "../api";

/** Passkeys need a browser that has them, on a page it trusts: HTTPS with a valid certificate, on a name. */
export function passkeysSupported() {
  return typeof window !== "undefined" && window.isSecureContext && "PublicKeyCredential" in window && !!navigator.credentials;
}

function fromBase64url(value: string): ArrayBuffer {
  const text = atob(value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "="));
  const bytes = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) bytes[i] = text.charCodeAt(i);
  return bytes.buffer;
}

function toBase64url(value: ArrayBuffer | null): string {
  if (!value) return "";
  let text = "";
  for (const byte of new Uint8Array(value)) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** The browser's errors, in words that say what to do. */
function explain(error: unknown): Error {
  const name = error instanceof DOMException ? error.name : "";
  if (name === "NotAllowedError" || name === "AbortError") return new Error("The passkey request was cancelled or timed out. Try again.");
  if (name === "InvalidStateError") return new Error("This device or password manager already has a passkey for your account here.");
  if (name === "SecurityError")
    return new Error("The browser refused passkeys on this address. They need the dashboard on a name, such as dg.example.com, with a certificate the browser trusts.");
  if (name === "NotSupportedError") return new Error("This browser or device can't make a passkey DeaconGuard accepts.");
  return error instanceof Error ? error : new Error(String(error));
}

/** Makes a passkey for the account the options name. */
export async function createPasskey(options: PasskeyOptions): Promise<PasskeyRegistration> {
  let credential: Credential | null;
  try {
    credential = await navigator.credentials.create({
      publicKey: {
        challenge: fromBase64url(options.challenge),
        rp: { id: options.rp_id, name: options.rp_name ?? "DeaconGuard" },
        user: { id: fromBase64url(options.user_id ?? ""), name: options.user_name ?? "", displayName: options.display_name ?? "" },
        pubKeyCredParams: (options.algorithms ?? [-7, -257]).map((alg) => ({ type: "public-key" as const, alg })),
        excludeCredentials: options.credentials.map((item) => ({
          type: "public-key" as const,
          id: fromBase64url(item.id),
          transports: item.transports as AuthenticatorTransport[] | undefined,
        })),
        authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
        attestation: "none",
        timeout: options.timeout,
      },
    });
  } catch (error) {
    throw explain(error);
  }
  if (!(credential instanceof PublicKeyCredential)) throw new Error("The browser made no passkey.");
  const response = credential.response as AuthenticatorAttestationResponse;
  const publicKey = response.getPublicKey?.();
  if (!publicKey) throw new Error("This browser doesn't give DeaconGuard the passkey's public key. Use a current version of Chrome, Edge, Safari or Firefox.");
  return {
    id: toBase64url(credential.rawId),
    client_data_json: toBase64url(response.clientDataJSON),
    authenticator_data: toBase64url(response.getAuthenticatorData()),
    public_key: toBase64url(publicKey),
    algorithm: response.getPublicKeyAlgorithm(),
    transports: response.getTransports?.() ?? [],
  };
}

/** Signs in with a passkey: any of this site's, or one of those the options allow. */
export async function signInWithPasskey(options: PasskeyOptions): Promise<PasskeyAssertion> {
  let credential: Credential | null;
  try {
    credential = await navigator.credentials.get({
      publicKey: {
        challenge: fromBase64url(options.challenge),
        rpId: options.rp_id,
        allowCredentials: options.credentials.map((item) => ({
          type: "public-key" as const,
          id: fromBase64url(item.id),
          transports: item.transports as AuthenticatorTransport[] | undefined,
        })),
        userVerification: "required",
        timeout: options.timeout,
      },
    });
  } catch (error) {
    throw explain(error);
  }
  if (!(credential instanceof PublicKeyCredential)) throw new Error("The browser gave no passkey.");
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: toBase64url(credential.rawId),
    client_data_json: toBase64url(response.clientDataJSON),
    authenticator_data: toBase64url(response.authenticatorData),
    signature: toBase64url(response.signature),
  };
}
