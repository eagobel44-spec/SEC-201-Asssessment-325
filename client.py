# client.py
# The program that each person runs (the owner and the team members).
# The first word after client.py is who you are.
#
#   python client.py alice keygen
#   python client.py alice register
#   python client.py alice create-team blue
#   python client.py alice invite bob
#   python client.py bob join blue
#   python client.py alice send
#   python client.py bob fetch
#
# Add --yes to invite or join to skip the question about the fingerprint.

import csv
import json
import os
import sys

import requests

import crypto
import protect

# Each person's files (their keys) are kept in their own folder, outside of the project,
# so that keys can't end up being uploaded with the code.
HOME = os.environ.get("SECURE_SHARE_HOME", os.path.join(os.path.expanduser("~"), ".secure_share"))

DEFAULT_SERVER = "http://127.0.0.1:8000"
DEFAULT_SERVER_KEY = os.path.join("server_files", "server_public.pem")
DEFAULT_DATASET = os.path.join("..", "make_dataset", "outputs", "synthetic", "npm_versions_clean.csv")


# ---------- small helpers ----------

# Where one of a person's files is.
def path(name, filename):
    return os.path.join(HOME, name, filename)


# Reads one of a person's files (stops if it is not there yet).
def read(name, filename):
    if not os.path.exists(path(name, filename)):
        sys.exit(f"{name} has no {filename} yet. Run keygen and register first.")
    with open(path(name, filename)) as f:
        return f.read()


# Saves one of a person's files.
def write(name, filename, text):
    os.makedirs(os.path.join(HOME, name), exist_ok=True)
    with open(path(name, filename), "w") as f:
        f.write(text)


# Sends a message to the server and gets the answer back.
# If the server refused it, the program stops and shows the reason.
def post(url, body):
    try:
        reply = requests.post(url, json=body, timeout=30).json()
    except requests.RequestException:
        sys.exit("Could not reach the server. Is it running?")
    if "error" in reply:
        sys.exit("Refused by the server: " + reply["error"])
    return reply


# Asks a yes or no question (skipped if --yes was typed).
def confirm(question):
    if "--yes" in sys.argv:
        return
    if input(question + " [y/n] ").strip().lower() != "y":
        sys.exit("Stopped.")


# ---------- STEP 1: keys ----------
# First: the client (owner or team member) generates RSA keys (public and private) for
# signatures. It also makes a diffie-hellman private key, which is used later when the
# owner invites them (the second diffie-hellman exchange).

def keygen(name):
    if os.path.exists(path(name, "rsa_private.pem")):
        sys.exit(f"{name} already has keys.")
    rsa_private = crypto.rsa_generate()
    write(name, "rsa_private.pem", crypto.private_key_to_text(rsa_private))
    write(name, "dh_private.txt", str(crypto.dh_private_key()))
    print(f"Keys created for {name}.")
    print("Fingerprint:", crypto.fingerprint(rsa_private.public_key()))


# Loads a person's RSA private key from their folder.
def load_rsa(name):
    return crypto.private_key_from_text(read(name, "rsa_private.pem"))


# ---------- STEP 2: registration ----------
# (Registration, let server learn client's public key and confirm the client really owns it)
# Then, the client creates a signature over its own public key with its own private key.
# The client sends over the public key with the signature. The same is done for its
# diffie-hellman public key.
# The client is also given the server's public key and checks the server's signatures
# against it. This is necessary so that all communication between the two are verified
# and can be traced to a person (non-repudiation).

def register(name, server_url=DEFAULT_SERVER, server_key_file=DEFAULT_SERVER_KEY):
    rsa_private = load_rsa(name)
    rsa_public_text = crypto.public_key_to_text(rsa_private.public_key())
    dh_public_text = str(crypto.dh_public_key(int(read(name, "dh_private.txt"))))

    post(server_url + "/register", {
        "name": name,
        "rsa_public_key": rsa_public_text,
        "dh_public_key": dh_public_text,
        "rsa_signature": crypto.rsa_sign(rsa_private, rsa_public_text.encode()),
        "dh_signature": crypto.rsa_sign(rsa_private, dh_public_text.encode()),
    })

    # The server's public key is saved, and this is the only server the client will trust.
    with open(server_key_file) as f:
        server_public_text = f.read()
    write(name, "server_public.pem", server_public_text)
    write(name, "server_url.txt", server_url)
    print(f"{name} is registered.")
    print("Server fingerprint:", crypto.fingerprint(crypto.public_key_from_text(server_public_text)))


# ---------- STEP 3: first diffie-hellman exchange (client and server) ----------
# First diffie-hellman exchange works with server and client, and both use the computed,
# shared key as a session key. Each side signs its diffie-hellman public key, so a third
# party cannot swap in its own. This happens at the start of every command below.

def connect(name):
    rsa_private = load_rsa(name)
    server_public = crypto.public_key_from_text(read(name, "server_public.pem"))
    url = read(name, "server_url.txt")

    # The client makes its diffie-hellman keys for this session, signs the public key
    # with its RSA private key, and sends the public key with the signature.
    dh_private = crypto.dh_private_key()
    dh_public_text = str(crypto.dh_public_key(dh_private))
    reply = post(url + "/hello", {
        "name": name,
        "dh_public_key": dh_public_text,
        "signature": crypto.rsa_sign(rsa_private, dh_public_text.encode()),
    })

    # Same in reverse: the client verifies the server's signature with the server's
    # public key that it saved, and stops if it fails (this is what stops a
    # man-in-the-middle, since they can't make the server's signature).
    signed = (dh_public_text + reply["dh_public_key"]).encode()
    if not crypto.rsa_verify(server_public, signed, reply["signature"]):
        sys.exit("Stopped: the server's signature does not verify. This is not the trusted server.")

    # Then both sides compute the shared key, which is the session key.
    session_key = crypto.dh_shared_key(int(reply["dh_public_key"]), dh_private)
    return {"name": name, "url": url, "id": reply["session_id"], "key": session_key,
            "rsa_private": rsa_private, "server_public": server_public}


# ---------- STEP 4: sending a message ----------
# The session key is used to encrypt any message in both directions with aes-gcm, so the
# message is encrypted and can't be decrypted within transit. The client also signs
# every message (a new signature each time) so the server can verify who sent it.

def message(session, action, **fields):
    request = json.dumps({"action": action, **fields}).encode()
    encrypted = crypto.aes_encrypt(session["key"], request)
    signature = crypto.rsa_sign(session["rsa_private"], encrypted.encode())
    reply = post(session["url"] + "/message", {
        "session_id": session["id"], "encrypted": encrypted, "signature": signature,
    })
    # The reply is decrypted with the same session key. If it was changed on the way,
    # aes-gcm fails and the client stops.
    try:
        return json.loads(crypto.aes_decrypt(session["key"], reply["encrypted"]))
    except ValueError:
        sys.exit("Stopped: the server's reply was changed on the way.")


# ---------- STEP 5: team keys and the second diffie-hellman exchange ----------

# Loads the team name and the two team keys from a person's folder.
def load_team(name):
    team = json.loads(read(name, "team.json"))
    return team["team"], crypto.to_bytes(team["hmac_key"]), crypto.to_bytes(team["column_key"])


# Saves the team name and the two team keys into a person's folder.
def save_team(name, team, hmac_key, column_key):
    write(name, "team.json", json.dumps({
        "team": team, "hmac_key": crypto.to_text(hmac_key), "column_key": crypto.to_text(column_key),
    }))


# The owner creates the team and the two team keys: one is for the aes-gcm encrypted
# columns and the other is for the hmac columns (pseudonyms for package names and
# publisher). The keys are made on the owner's side and the server does not get them.
def create_team(name, team):
    session = connect(name)
    message(session, "create_team", team=team)
    save_team(name, team, crypto.new_key(), crypto.new_key())
    print(f"Team {team} created. Two team keys made: one for HMAC pseudonyms, one for encrypting columns.")


# Second diffie-hellman exchange works with the server acting as an intermediary, where
# the owner and team member send their public keys to each other. The computed shared key
# of this exchange is then used to encrypt two team keys (created by owner) with aes-gcm,
# which is sent to the team member.
def invite(name, user):
    team, hmac_key, column_key = load_team(name)
    session = connect(name)

    # The owner gets the team member's public keys from the server, and compares the
    # fingerprint with the one the team member sees (so the server can't hand over the
    # wrong person's key).
    info = message(session, "get_user", user=user)
    their_rsa = crypto.public_key_from_text(info["rsa_public_key"])
    print(f"{user}'s fingerprint:", crypto.fingerprint(their_rsa))
    confirm(f"Is that the fingerprint {user} sees on their own screen?")

    # The owner verifies the team member's signature on their diffie-hellman public key
    # (the owner checks this themselves, the server is only carrying it).
    if not crypto.rsa_verify(their_rsa, info["dh_public_key"].encode(), info["dh_signature"]):
        sys.exit(f"Stopped: {user}'s Diffie-Hellman public key is not signed by {user}.")

    # Then the owner makes their own diffie-hellman keys and computes the shared key
    # that only the owner and the team member can compute.
    my_dh_private = crypto.dh_private_key()
    my_dh_public_text = str(crypto.dh_public_key(my_dh_private))
    shared_key = crypto.dh_shared_key(int(info["dh_public_key"]), my_dh_private)

    # The two team keys are encrypted with the shared key (aes-gcm), signed by the owner,
    # and left on the server for the team member.
    sealed_keys = crypto.aes_encrypt(shared_key, hmac_key + column_key)
    signature = crypto.rsa_sign(session["rsa_private"], (my_dh_public_text + sealed_keys).encode())
    message(session, "invite", team=team, user=user,
            owner_dh_public_key=my_dh_public_text, sealed_keys=sealed_keys, signature=signature)
    print(f"{user} invited to {team}. The team keys were encrypted so only {user} can open them.")


# The team member gets these two keys and decrypts them with the computed shared key
# that only him and the owner has.
def join(name, team):
    session = connect(name)
    invitation = message(session, "join", team=team)

    owner_rsa = crypto.public_key_from_text(invitation["owner_rsa_public_key"])
    print(f"Invited by {invitation['owner']}, fingerprint:", crypto.fingerprint(owner_rsa))
    confirm("Is that the owner's fingerprint?")

    # First, the team member verifies the owner's signature with the owner's public key.
    signed = (invitation["owner_dh_public_key"] + invitation["sealed_keys"]).encode()
    if not crypto.rsa_verify(owner_rsa, signed, invitation["signature"]):
        sys.exit("Stopped: the invitation is not signed by the owner.")

    # Then, the team member computes the same shared key (with the owner's diffie-hellman
    # public key and their own private key), and decrypts the team keys with it.
    my_dh_private = int(read(name, "dh_private.txt"))
    shared_key = crypto.dh_shared_key(int(invitation["owner_dh_public_key"]), my_dh_private)
    try:
        keys = crypto.aes_decrypt(shared_key, invitation["sealed_keys"])
    except ValueError:
        sys.exit("Stopped: the team keys could not be decrypted.")
    save_team(name, team, keys[:32], keys[32:])
    print(f"{name} joined {team} and now holds the two team keys.")


# ---------- STEP 6 and 7: protecting the dataset and sending it ----------

# Checks the server's signature on a verdict with the server's public key, so the client
# knows the verdict came from the server and was not changed.
def verdict_is_genuine(session, row_id, verdict, signature):
    text = (row_id + "|" + verdict).encode()
    return crypto.rsa_verify(session["server_public"], text, signature)


# Finally, the team keys are used to encrypt confidential columns of the dataset, HMAC
# the two main identifiers (publisher and package name) and turn into pseudonyms.
# This is done before anything is sent, and then it is sent to the server.
def send(name, dataset=DEFAULT_DATASET):
    team, hmac_key, column_key = load_team(name)
    with open(dataset, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    protected = [protect.protect_row(row, hmac_key, column_key) for row in rows]

    session = connect(name)
    reply = message(session, "send", team=team, rows=protected)

    # The server sends back a verdict for each row (suspicious or not flagged), signed
    # with its own private key. Each signature is verified here.
    # The verdicts are also counted next to my own labels (the labels were not sent),
    # just to see how the server did.
    counts = {}
    for row, item in zip(rows, reply["verdicts"]):
        if not verdict_is_genuine(session, item["row_id"], item["verdict"], item["signature"]):
            sys.exit("Stopped: a verdict's signature does not verify.")
        key = (row.get("label", "?"), item["verdict"])
        counts[key] = counts.get(key, 0) + 1

    print(f"Sent {len(rows)} rows to team {team}. Every verdict's signature verified.")
    for (label, verdict), count in sorted(counts.items()):
        print(f"  my label: {label:<10} server verdict: {verdict:<12} rows: {count}")


# ---------- STEP 8: fetching the dataset ----------

# The team member fetches the rows and verdicts from the server (the server checks the
# team member's signature and that they belong to the team before sending it).
# The team member takes the dataset and decrypts the encrypted columns using the given
# team keys.
def fetch(name):
    team, hmac_key, column_key = load_team(name)
    session = connect(name)
    reply = message(session, "fetch", team=team)

    print(f"{len(reply['rows'])} rows in team {team}:")
    print(f"  {'package':<24} {'version':<10} {'verdict':<12} sent by")
    for item in reply["rows"]:
        row_id = item["row"]["row_id"]
        if not verdict_is_genuine(session, row_id, item["verdict"], item["signature"]):
            sys.exit("Stopped: a verdict's signature does not verify.")
        row = protect.unprotect_row(item["row"], column_key)
        print(f"  {row['package']:<24} {row['version']:<10} {item['verdict']:<12} {item['sender']}")


# ---------- the commands ----------

# Reads what was typed (the name, the command, and anything after it) and runs
# the matching function above.
def main():
    args = [a for a in sys.argv[1:] if a != "--yes"]
    if len(args) < 2:
        sys.exit("usage: python client.py NAME keygen | register | create-team TEAM | "
                 "invite USER | join TEAM | send | fetch")
    name, command, extra = args[0], args[1], args[2:]

    if command == "keygen":
        keygen(name)
    elif command == "register":
        register(name, *extra)
    elif command == "create-team" and extra:
        create_team(name, extra[0])
    elif command == "invite" and extra:
        invite(name, extra[0])
    elif command == "join" and extra:
        join(name, extra[0])
    elif command == "send":
        send(name, *extra)
    elif command == "fetch":
        fetch(name)
    else:
        sys.exit("unknown command, or a name is missing after it")


if __name__ == "__main__":
    main()
