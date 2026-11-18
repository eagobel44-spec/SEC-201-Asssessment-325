# secure_share

A team shares a dataset through a central server. The server stores the
data and passes it to team members, but cannot read the sensitive parts.

## Files

| File | What it is |
|---|---|
| `crypto.py` | every cryptography function: RSA signatures, Diffie-Hellman, AES-GCM, HMAC |
| `protect.py` | protects one dataset row before it is sent (remove, pseudonym, range, encrypt) |
| `server.py` | the central server |
| `client.py` | the program each person runs |
| `test_system.py` | the tests |
| `demo.ps1` | runs the whole flow once |

## Setup

```
pip install -r requirements.txt
```

The dataset comes from the other folder. Build it once:

```
python ..\make_dataset\main.py
```

## Running it

Terminal 1, the server:

```
python server.py keygen
python server.py run
```

Terminal 2, the clients. The first word after `client.py` is who you are:

```
python client.py alice keygen
python client.py alice register
python client.py bob keygen
python client.py bob register

python client.py alice create-team blue
python client.py alice invite bob
python client.py bob join blue

python client.py alice send
python client.py bob fetch
```

`invite` and `join` show a fingerprint and ask you to confirm it. Add
`--yes` to skip the question.

Or run everything at once: `.\demo.ps1`

## How it works

| Step | What happens | Technique | Lecture |
|---|---|---|---|
| 1 | Server and each client make an RSA key pair | RSA | 5, 7 |
| 2 | The client registers: it sends its RSA public key and its Diffie-Hellman public key, each signed. The server verifies and stores them. The client saves the server's public key | digital signature | 7 |
| 3 | Client and server exchange signed Diffie-Hellman public keys and compute the same shared key. That is the session key | Diffie-Hellman, SHA-256 | 5, 6 |
| 4 | Every message is encrypted with the session key and signed | AES-GCM, digital signature | 4, 7 |
| 5 | The owner makes two team keys. The owner and a member do a second Diffie-Hellman exchange through the server; the shared key encrypts the team keys | Diffie-Hellman, AES-GCM | 5, 4 |
| 6 | The dataset is protected on the client: columns removed, names turned into pseudonyms, numbers into ranges, confidential columns encrypted | HMAC, AES-GCM, anonymization | 7, 4, 8 |
| 7 | The owner sends it. The server checks the signature and team membership, stores the rows, and signs a verdict for each | digital signature | 7 |
| 8 | A member fetches the rows, verifies the server's signature, and decrypts the encrypted columns | AES-GCM | 4 |

The step numbers are also in the comments of `server.py` and `client.py`.

## The keys

| Key | Who has it | Used for |
|---|---|---|
| RSA private key | its owner only | signing |
| RSA public key | anyone | checking signatures |
| Session key | one client and the server | encrypting messages in transit |
| Shared key from the second exchange | owner and one member | encrypting the two team keys, once |
| Team column key | team members | encrypting and decrypting the confidential columns |
| Team HMAC key | team members | making the pseudonyms |

## Where things are stored

- Server: `server_files/` (its keys and `data.json`).
- Each client: `.secure_share/<name>/` in your user folder.

## Tests

```
python -m pytest test_system.py -q
```

20 tests: the crypto functions, the whole flow, and the refusals (wrong
server key, man-in-the-middle, tampered message, tampered signature,
outsider, forged verdict).

## Known weaknesses (opportunities for improvement)

- A captured message can be sent again (no replay protection).
- A session never expires while the server is running.
- A member who leaves still has the team keys.
- The server can still work out which package a row is, from the publish
  time and version, which are sent readable.
- The server could swap two encrypted values between rows without it
  being detected.
- Key files are not password protected.
- The verdict comes from a few hand-written rules, not a trained model.
- One team per client, and the server handles one request at a time.
