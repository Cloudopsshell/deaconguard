---
title: Accounts and sign-in
description: Dashboard accounts and their roles, two-step sign-in with passkeys or an authenticator app, recovery codes, appearance, and what to do when someone loses access.
---

The server's dashboard needs an account to sign in. [Local mode](./local-mode.md) has no accounts: it only listens on `127.0.0.1`.

## Roles

Every account has one of three roles. Give each person the least they need.

| | Viewer | Operator | Admin |
| --- | :-: | :-: | :-: |
| See hosts, findings, vulnerabilities, scan reports, images, network targets, schedules and logs | ✓ | ✓ | ✓ |
| My account: own password, two-step sign-in, appearance, sessions | ✓ | ✓ | ✓ |
| Scan now, cancel a queued scan, answer sudo prompts | | ✓ | ✓ |
| Create, change, run and delete schedules; download the log | | ✓ | ✓ |
| Add, scan and remove [registry images](./images.md) | | ✓ | ✓ |
| Scan [network targets](./network.md#in-the-dashboard) now | | ✓ | ✓ |
| Delete scans, change a host's sudo setting | | ✓ | ✓ |
| Enroll machines (enrollment tokens), remove hosts | | | ✓ |
| Save [registry logins](./images.md#registries-and-logins) for private images | | | ✓ |
| Add, change and remove [network targets](./network.md#in-the-dashboard) | | | ✓ |
| The **Accounts** page, Require two-step sign-in, the **Audit log** | | | ✓ |

The server checks the role on every request, not just the dashboard: a viewer who calls the API directly is refused. The dashboard hides what a role can't use, and **My account** says which role you have.

Accounts from before DeaconGuard 0.11.0 are admins, so nobody loses access when upgrading. The first account, made by setup, is an admin. On the **Accounts** page, new accounts are viewers until you choose otherwise.

## Two-step sign-in

With two-step sign-in, a stolen or guessed password alone can't sign in. There are two ways, and an account can use both:

- a **passkey**, which signs you in with your fingerprint, face or device PIN, with no password or code to type: see [Passkeys](#passkeys);
- an **authenticator app**, which shows a 6-digit code that DeaconGuard asks for after your password.

To set up an authenticator app, open **My account** (your name at the bottom of the sidebar), then **Set up an authenticator app**:

1. Scan the QR code with your authenticator app, or type the key shown under it.
2. Enter the 6-digit code the app shows.
3. Save the 10 **recovery codes** that appear. They are shown only once.

Until two-step sign-in is on, every page shows a reminder, and the sidebar marks your account. You can hide the reminder; it comes back the next time you sign in.

### Passkeys

A passkey is a key pair your device or password manager makes for this dashboard. DeaconGuard keeps only the public key; signing in proves you hold the private key, after your device checks your fingerprint, face or PIN. So a passkey is two steps by itself, and it can't be phished: it only works on the dashboard's own address. Passkeys need DeaconGuard 1.7.0 or later.

**Add one:** on **My account**, under **Passkeys**, choose **Add a passkey**, give it a name and your password, and let the browser save it: on this device, on your phone, or in a password manager such as iCloud Keychain, Google Password Manager, 1Password or Bitwarden. A passkey in a password manager works on your other devices too. An account can have up to 20.

**Sign in:** on the sign-in page, choose **Sign in with a passkey**. With a passkey, your password also asks for one as its second step, so either way works.

**Rename or remove** one with the buttons next to it. Removing it there stops it signing in; delete it from the device or password manager too.

Passkeys need the dashboard on a **name with a certificate the browser trusts**, such as `https://dg.example.com:8443` with your own certificate (`--tls-cert`, see [Server](./server.md)). Browsers refuse passkeys on IP addresses and on the self-signed certificate DeaconGuard makes on its first start, and **My account** says so. A passkey belongs to the name it was made on: after moving the dashboard to a new name, add them again.

### Authenticator apps

DeaconGuard uses the standard time-based codes (TOTP, RFC 6238: 6 digits, a new code every 30 seconds), so any authenticator app works, for example:

- Google Authenticator, Microsoft Authenticator
- Bitwarden, 1Password, Proton Pass, KeePassXC, Apple Passwords (iOS 18, macOS 15 and later)
- Ente Auth, 2FAS, Aegis (Android)

An app that backs up or syncs its codes, like a password manager, means a lost phone doesn't lock you out.

The server's clock must be right, because codes depend on the time; a few seconds' difference doesn't matter. Each code works once.

### Recovery codes

Each recovery code signs you in once instead of a code from the app: on the sign-in page, choose **Use a recovery code**. Keep them in your password manager, or print them.

**My account** shows how many are left. With 2 or fewer, DeaconGuard reminds you to create new ones; **New recovery codes** replaces all of them.

### A new phone

On **My account**, **Move to a new phone or app** shows a new QR code. The old app keeps working until the new one is confirmed; then other sessions are signed out.

### Require it for everyone

On the **Accounts** page, **Require it** makes two-step sign-in mandatory: an authenticator app or a passkey. Anyone without either is asked to set one up right after signing in and can't use the dashboard until they do. Turn it on for yours first; DeaconGuard won't require it while your own account lacks it. While it is required, an account keeps at least one: the app can be turned off only with a passkey, and the last passkey can be removed only with the app.

## My account

Every account manages itself on **My account** (your name at the bottom of the sidebar, which also shows your role):

- **Authenticator app:** set it up, move it to a new phone, create new recovery codes, or turn it off (unless two-step sign-in is required and you have no passkey).
- **Passkeys:** add, rename and remove them.
- **Password:** at least 12 characters. Changing it signs out your other sessions.
- **Appearance:** light, dark, or System, which follows your computer's setting as it changes, and one of five themes: Indigo (the default), Ocean, Teal, Plum and Graphite. It is saved to your account, so it follows you to every browser. The buttons at the bottom of the sidebar change it too. Severity colors are the same in every theme.
- **Sessions:** every browser signed in to your account, with its address and when it was last used. Sign out one, or all others at once. If you see one you don't recognize, sign it out and change your password.

Sessions last 12 hours.

### API tokens

**My account → API tokens** creates tokens for scripts and tools to use the API as you, with a role up to your own; see [API](../reference/api.md).

## Managing accounts

Admins use the **Accounts** page. It lists every account with its role, two-step sign-in status and last sign-in.

**New account:** choose a username, a role and a temporary password. Give the password to the person privately; at their first sign-in they must choose their own before anything else.

**Manage**, next to each account, offers:

- **Change role:** signs them out, so the new role applies as soon as they sign in again.
- **Set temporary password:** for someone who forgot theirs. It signs them out everywhere, and they choose a new one at the next sign-in.
- **Reset two-step sign-in:** for someone who lost their phone and their recovery codes, or their passkeys. Their authenticator, recovery codes and passkeys stop working and they are signed out; they sign in with their password and set it up again. Check that it is really them first.
- **Disable / Enable:** a disabled account can't sign in and is signed out, but keeps its settings.
- **Remove:** deletes the account and signs it out. The audit log keeps its entries.

You manage your own account on **My account**, not here, so you can't lock yourself out by accident. DeaconGuard also keeps at least one admin that can sign in: the last one can't be demoted, disabled or removed.

Every change is recorded in the **Audit log**.

## When someone loses access

| What happened | What to do |
| --- | --- |
| Lost their phone, still has recovery codes | Sign in with **Use a recovery code**, then **Move to a new phone or app** on My account. |
| Lost their phone and recovery codes | An admin uses **Manage → Reset two-step sign-in** on the Accounts page. |
| Lost a passkey, has another or the app | Sign in with that, then remove the lost one on My account. |
| Lost their only passkey | An admin uses **Manage → Reset two-step sign-in**. |
| Forgot their password | An admin uses **Manage → Set temporary password**. |
| You are the only admin | On the server: `sudo -u deaconguard deaconguard user mfa-reset NAME` or `sudo -u deaconguard deaconguard user passwd NAME`. |

There is no "forgot password" email: DeaconGuard sends no email, and resetting by email would make your mailbox a way into the dashboard. Keep two admin accounts, so one can always help the other.

## From the command line

On the server, run these as the `deaconguard` user:

```bash
sudo -u deaconguard deaconguard user add alice                 # an admin; asks for a password
sudo -u deaconguard deaconguard user add bob --role operator   # or --role viewer
sudo -u deaconguard deaconguard user role bob viewer           # signs bob out
sudo -u deaconguard deaconguard user passwd alice
sudo -u deaconguard deaconguard user mfa-reset alice  # removes the app and passkeys, signs out
sudo -u deaconguard deaconguard user list             # with roles and two-step sign-in status
sudo -u deaconguard deaconguard user remove alice
```

Accounts created on the command line choose their own password there, so they don't have to change it at the first sign-in. They are admins unless `--role` says otherwise.

## How it is stored

Passwords are stored as PBKDF2 hashes and recovery codes as SHA-256 hashes. For passkeys, only the public key is kept, which can't sign anyone in. The authenticator key has to be readable to check codes, so it is stored as is in `deaconguard.db`: protect the database and its backups as you would the server's certificate key. See [Backup and restore](./backup-and-restore.md).
