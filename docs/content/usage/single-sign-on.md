---
title: Single sign-on
description: Sign in to the dashboard with your identity provider over OpenID Connect, such as Microsoft Entra ID, Google, Okta, Keycloak or Authentik, with roles from its groups.
---

With single sign-on, people sign in to the dashboard with your organisation's identity provider, over OpenID Connect. Their password, two-step sign-in and when they leave are managed there. It needs DeaconGuard 1.7.0 or later.

Password accounts keep working next to it. **Keep at least one admin with a password and two-step sign-in**, so you can still sign in when the provider is down or its settings change.

## Set it up

1. In DeaconGuard, open **Settings → Single sign-on** at the address people use for the dashboard, and copy the **Redirect URI**, such as `https://dg.example.com:8443/api/login/sso/callback`.
2. At your provider, register an application (a "web" or "confidential" client) with that redirect URI, and note its **issuer URL**, **client ID** and **client secret**.
3. Back in DeaconGuard, fill in those three, choose **Offer single sign-on on the sign-in page**, and **Save**. DeaconGuard reads the provider's discovery document before it saves, so a wrong issuer is caught there.

The sign-in page then shows a button, **Sign in with single sign-on** unless you give it other text, such as "Sign in with Entra ID".

The dashboard needs a certificate the provider's users' browsers trust, and the server must reach the provider over HTTPS. With your own certificate authority, point the server at it, for example with `SSL_CERT_FILE`.

### Providers

| Provider | Issuer URL | Notes |
| --- | --- | --- |
| Microsoft Entra ID | `https://login.microsoftonline.com/TENANT-ID/v2.0` | Register an app with a **Web** redirect URI and a client secret. For roles from groups, add a groups claim to the ID token (**Token configuration**); it sends group object IDs, so use those as group names here, or have it send names for groups synced from on-premises. |
| Google | `https://accounts.google.com` | Create an OAuth client of type **Web application**. Google sends no groups: limit sign-in with **Allowed email domains**, and give roles on the Accounts page. |
| Okta | `https://YOUR-ORG.okta.com` or an authorization server's URL | Create an **OIDC web application**. For groups, add a groups claim to the ID token and put `groups` in **Extra scopes**. |
| Keycloak | `https://keycloak.example.com/realms/REALM` | Create an OpenID Connect client with **Client authentication** on. For groups, add a **Group Membership** mapper to the ID token, with **Full group path** off. |
| Authentik | `https://authentik.example.com/application/o/SLUG/` | Create an OAuth2/OpenID provider of type **Confidential**. Its `profile` scope sends `groups`. |
| Dex | `https://dex.example.com/dex` | Add a static client. Put `groups` in **Extra scopes** for groups. |

Others work too, if they publish an OpenID discovery document and sign ID tokens with RS256, RS384, RS512, PS256, ES256 or ES384.

## Accounts

The first time someone signs in, DeaconGuard makes their account, named by their **email**, which the provider must have verified, or by their **username** (`preferred_username`) if you choose that. The account is linked to the provider's permanent ID for the person, not to the name, so a renamed person keeps their account.

These accounts have no password in DeaconGuard: the **Accounts** page marks them **Single sign-on**, and **My account** shows their appearance, API tokens and sessions, but no password, passkeys or authenticator app. [Require two-step sign-in](./accounts.md#require-it-for-everyone) doesn't apply to them; require it at your provider instead.

If a password account already has the name, the sign-in is refused, so nobody takes over an existing account by choosing a name at the provider. Rename or remove the password account first.

To stop someone signing in, remove them at the provider, or **Disable** their account on the Accounts page. Removing them at the provider leaves a session they already have until it expires, at most 12 hours; **Disable** also signs them out at once.

## Who may sign in, and roles

By default, anyone your provider signs in to this application may use DeaconGuard, as a **Viewer**, or the role you choose for everyone. Under **Who may sign in, and roles from groups**:

- **Allowed email domains**, such as `example.com`, admit only people with a verified email there.
- **Allowed groups** admit only their members, and members of the admin and operator groups.
- **Admin groups** and **Operator groups** give their members that role. With either set, **roles follow the groups at every sign-in**: someone removed from the admin group is an operator or viewer the next time they sign in, and a role an admin sets on the Accounts page lasts until then. The last admin that can sign in is never demoted this way.
- **Groups claim** is the ID token claim that lists groups, `groups` unless your provider uses another name.
- **Extra scopes** are asked for besides `openid`, `email` and `profile`, such as `groups`, which some providers need to send groups.

## When it fails

The sign-in page says why, without details a stranger could use, and the **Audit log** and the server's log have the details:

| The sign-in page says | What to check |
| --- | --- |
| took too long, or was started in another browser | The sign-in must finish within 10 minutes, in the browser that started it. |
| couldn't complete the sign-in with your identity provider | The client ID, the secret, and that the redirect URI registered matches the one in Settings exactly. |
| answer couldn't be verified | The server's clock, and that the provider signs ID tokens with a supported algorithm. |
| isn't in a group allowed | The person's groups, the groups claim, and **Extra scopes**. The audit log says how many groups the provider sent. |
| didn't send a verified email or username | The provider's email verification, or choose **Username** for new accounts. |
| already exists and signs in with a password | Rename or remove the password account. |

## Security

DeaconGuard uses the authorization code flow with PKCE, a `state` tied to the browser by a cookie, and a `nonce` in the ID token. It checks the ID token's signature against the provider's published keys, and its issuer, audience, expiry and nonce. The provider is only reached over HTTPS. The client secret is stored in `deaconguard.db` and never shown again; protect the database as you would the server's certificate key. API tokens can't read or change these settings.
