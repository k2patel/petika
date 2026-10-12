# Managed accounts in the CLI

The CLI signs in with your Petika-managed account. The browser confirms your identity;
collection encryption and decryption still happen locally. No npm or external HTTP
executable is required.

```sh
petika login --server https://petika.example.org
# Open the printed URL, enter the terminal code, confirm your account password,
# choose “Approve this CLI”, and confirm. The CLI completes automatically.
petika whoami
petika collections
petika status
petika --store personal.petika pull
petika --store personal.petika generate 'Example login'
petika --store personal.petika push --revision 1
petika logout
```

Use the revision printed by `pull`, not necessarily `1`. `status` reports the current
server revision and mirror state. `push --revision 0` initializes an empty remote
collection from an existing local store. Never substitute a newer revision merely to
force a conflicted upload: first pull to a separate file and reconcile the changes.
There is no automatic merge or background CLI sync in this release.

`pull` refuses an existing local file unless you explicitly pass `--replace`. It
verifies the downloaded ciphertext with your local collection passphrase before
writing. A wrong passphrase leaves the existing file untouched. `push` also verifies
the local file before uploading only its ciphertext. Offline `list`, `get`, `put`,
`generate`, and other local commands continue to work without a server session.

For groups, use `--collection ID` on `pull`, `push`, or `status`, with an ID from
`collections`. The default is your personal collection. Read-only memberships permit
downloads but not uploads. Group decryption still needs the separately shared group
passphrase; browser approval does not deliver encryption keys.

## Session storage and revocation

A versioned `session.json` beside the default user-data store contains the server
origin and bearer credential. Override it with `--session-file PATH` for separate
accounts or servers. It contains no account password or collection passphrase, but
**the bearer credential is sensitive and is not encrypted at rest**. On Unix the file
is owner-only (0600) and checked on access. On Windows use a private user-profile
location with restricted inherited ACLs; this release does not configure Windows ACLs
or integrate an OS credential manager. Do not put this file in Git or shared storage.
The session path must differ from the encrypted store path.

Sessions expire after eight hours. Logout revokes the CLI session and clears its local
file. `logout --local` clears only the local file when the server is unavailable; the
server token remains valid until expiry or revocation. Changing the account password
in the web UI or disabling the account revokes CLI sessions. Server restart also ends
all sessions and pending approvals. There are no refresh tokens. Use `logout --local`
then `login` when replacing an expired session.

HTTPS with certificate validation is required, except literal loopback addresses or
`localhost` for local development. Redirects are not followed. There is no insecure
TLS bypass. Private-CA trust configuration is not implemented yet.

## Approval protocol

This is a Petika-specific device approval protocol, inspired by the separation of
user and device codes in [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628.html), not
an OAuth or OpenID Connect implementation. Optional OIDC remains future work.

- The CLI gets a random 256-bit device secret and separate 40-bit human code.
- The browser URL contains neither code; the user manually types the terminal code.
- Approval requires a browser session, account-password reauthentication, and an
  explicit decision. Denial is selected initially. Never approve someone else's code.
- Requests expire after ten minutes, can be answered once, and can be redeemed once.
- Polling is limited to every five seconds. Requests are capped at 30/minute and 100
  pending per process; password reauthentication uses the shared login rate limit.
- Redemption verifies that the approving browser session is still valid. The issued
  CLI bearer session has the same account privileges and current group permissions.

The browser shows the privilege being granted before approval. Device-code phishing
remains possible if someone persuades a user to approve their request. These controls
are not a claim of phishing resistance. Deploy behind HTTPS and proxy rate limits.
