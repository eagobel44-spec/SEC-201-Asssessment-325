# server.py
# The central server. There are three places data goes through: the owner, team member,
# and server. The server stores what the clients send and gives it to team members that
# ask for it, but it cannot read the encrypted columns or the team keys.
#
#   python server.py keygen      generates the server's RSA keys (public and private)
#   python server.py run         starts the server (port 8000)

import json
import os
import secrets
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

import crypto

# The folder where the server keeps its key files and its data file.
SERVER_DIR = os.environ.get("SECURE_SHARE_SERVER_DIR", "server_files")

# Everything the server remembers. The "data" part is saved into a file, but the
# "sessions" part (the session keys) is only kept in memory and never saved.
STATE = {
    "private_key": None,
    "data": {"users": {}, "teams": {}, "rows": {}},
    "sessions": {},        # session id -> {"name": ..., "key": session key}
}


# This is used when the server refuses something. The text is sent back to the client.
class Refused(Exception):
    pass


# ---------- key files and the data file ----------

# First: the server generates its RSA keys (public and private) and saves them.
# The public key file is the one that is given to the clients.
def keygen():
    os.makedirs(SERVER_DIR, exist_ok=True)
    private_path = os.path.join(SERVER_DIR, "server_private.pem")
    if os.path.exists(private_path):
        sys.exit("The server already has a key. Delete server_files/ to start over.")
    private_key = crypto.rsa_generate()
    with open(private_path, "w") as f:
        f.write(crypto.private_key_to_text(private_key))
    with open(os.path.join(SERVER_DIR, "server_public.pem"), "w") as f:
        f.write(crypto.public_key_to_text(private_key.public_key()))
    print("Server keys created in", SERVER_DIR)
    print("Server fingerprint:", crypto.fingerprint(private_key.public_key()))


# Loads the server's private key and the saved data when the server starts.
def load():
    with open(os.path.join(SERVER_DIR, "server_private.pem")) as f:
        STATE["private_key"] = crypto.private_key_from_text(f.read())
    data_path = os.path.join(SERVER_DIR, "data.json")
    if os.path.exists(data_path):
        with open(data_path) as f:
            STATE["data"] = json.load(f)
    else:
        STATE["data"] = {"users": {}, "teams": {}, "rows": {}}
    STATE["sessions"] = {}


# Saves the data into the file (users, teams and the stored rows).
def save():
    with open(os.path.join(SERVER_DIR, "data.json"), "w") as f:
        json.dump(STATE["data"], f, indent=1)


# ---------- STEP 2: registration ----------
# (Registration, let server learn client's public key and confirm the client really owns it)
# The client sends over its public key with the signature. Then, the server verifies it
# with the signature and the signed public key (the signed public key works two roles:
# it is what was signed, and it is the key that checks the signature. No real message is
# signed yet), and stores the public key on file (checks incoming signatures with public key).
# The client's diffie-hellman public key is signed and stored the same way, since it is
# needed later for the second diffie-hellman exchange.

def register(body):
    name = body["name"]
    rsa_public_text = body["rsa_public_key"]
    dh_public_text = body["dh_public_key"]
    public_key = crypto.public_key_from_text(rsa_public_text)

    if not crypto.rsa_verify(public_key, rsa_public_text.encode(), body["rsa_signature"]):
        raise Refused("signature on the public key does not verify")
    if not crypto.rsa_verify(public_key, dh_public_text.encode(), body["dh_signature"]):
        raise Refused("signature on the Diffie-Hellman public key does not verify")

    # A name can't be taken over by someone with a different key.
    users = STATE["data"]["users"]
    if name in users and users[name]["rsa_public_key"] != rsa_public_text:
        raise Refused("that name is already registered with a different key")

    # The public key is stored on file, so that later messages (each with its own new
    # signature) can be verified.
    users[name] = {
        "rsa_public_key": rsa_public_text,
        "dh_public_key": dh_public_text,
        "dh_signature": body["dh_signature"],
    }
    save()
    return {"ok": True}


# ---------- STEP 3: first diffie-hellman exchange (client and server) ----------
# First diffie-hellman exchange works with server and client, and both use the computed,
# shared key as a session key. Each side signs its diffie-hellman public key, so a third
# party cannot swap in its own.

def hello(body):
    name = body["name"]
    if name not in STATE["data"]["users"]:
        raise Refused("not registered")
    client_rsa = crypto.public_key_from_text(STATE["data"]["users"][name]["rsa_public_key"])

    # The server verifies the client's signature on its diffie-hellman public key, with
    # the public key that was stored at registration. It refuses if it fails.
    client_dh_text = body["dh_public_key"]
    if not crypto.rsa_verify(client_rsa, client_dh_text.encode(), body["signature"]):
        raise Refused("signature does not verify")

    # Then the server makes its own diffie-hellman keys (new ones for every session) and
    # computes the shared key, which is the session key.
    server_dh_private = crypto.dh_private_key()
    server_dh_text = str(crypto.dh_public_key(server_dh_private))
    try:
        session_key = crypto.dh_shared_key(int(client_dh_text), server_dh_private)
    except ValueError as error:
        raise Refused(str(error))

    session_id = secrets.token_hex(16)
    STATE["sessions"][session_id] = {"name": name, "key": session_key}

    # Same in reverse: the server signs both public keys with its own private key, so
    # that the client can verify it is not speaking through a third unknown party.
    signature = crypto.rsa_sign(STATE["private_key"], (client_dh_text + server_dh_text).encode())
    return {"session_id": session_id, "dh_public_key": server_dh_text, "signature": signature}


# ---------- STEP 4: every message after that ----------
# The session key is used to encrypt any incoming messages from both directions with
# aes-gcm, so the message is encrypted and can't be decrypted within transit.
# Every message is also signed by the client.

def message(body):
    session = STATE["sessions"].get(body["session_id"])
    if session is None:
        raise Refused("unknown session")
    name = session["name"]
    client_rsa = crypto.public_key_from_text(STATE["data"]["users"][name]["rsa_public_key"])

    # First, the signature is checked with the public key on file. Each message has its
    # own new signature, so this is how the server knows who it came from.
    if not crypto.rsa_verify(client_rsa, body["encrypted"].encode(), body["signature"]):
        raise Refused("signature does not verify")

    # Then, the message is decrypted with the session key. If the message was changed
    # on the way, aes-gcm fails here and the message is refused.
    try:
        request = json.loads(crypto.aes_decrypt(session["key"], body["encrypted"]))
    except ValueError:
        raise Refused("message could not be decrypted")

    # Then, the server does what the message asked for.
    actions = {
        "create_team": create_team, "get_user": get_user, "invite": invite,
        "join": join, "send": send, "fetch": fetch,
    }
    if request.get("action") not in actions:
        raise Refused("unknown action")
    answer = actions[request["action"]](name, request)

    # Finally, the reply is encrypted with the same session key and sent back.
    return {"encrypted": crypto.aes_encrypt(session["key"], json.dumps(answer).encode())}


# ---------- STEP 5: teams and the second diffie-hellman exchange ----------
# Second diffie-hellman exchange works with the server acting as an intermediary, where
# the owner and team member send their public keys to each other. The server carries
# and stores these, but it never has the shared key or the team keys.

# The owner creates a team. Only the team name is stored here (the two team keys are
# created by the owner and are not sent to the server).
def create_team(name, request):
    team = request["team"]
    if team in STATE["data"]["teams"]:
        raise Refused("a team with that name already exists")
    STATE["data"]["teams"][team] = {"owner": name, "members": [name], "invites": {}}
    STATE["data"]["rows"][team] = {}
    save()
    return {"ok": True}


# Gives the owner the public keys of the team member that is being invited
# (only public keys, so there is nothing secret here).
def get_user(name, request):
    user = STATE["data"]["users"].get(request["user"])
    if user is None:
        raise Refused("no such user")
    return user


# The owner leaves the encrypted team keys here for the team member. The server stores
# them, but it can't decrypt them (it does not have the shared key that only the owner
# and the team member have). Only the owner of the team can invite.
def invite(name, request):
    team = STATE["data"]["teams"].get(request["team"])
    if team is None:
        raise Refused("no such team")
    if team["owner"] != name:
        raise Refused("only the team owner can invite")
    if request["user"] not in STATE["data"]["users"]:
        raise Refused("no such user")
    team["invites"][request["user"]] = {
        "owner_dh_public_key": request["owner_dh_public_key"],
        "sealed_keys": request["sealed_keys"],
        "signature": request["signature"],
    }
    if request["user"] not in team["members"]:
        team["members"].append(request["user"])
    save()
    return {"ok": True}


# The team member gets the encrypted team keys that the owner left for them, with the
# owner's public keys so the team member can verify the owner's signature.
def join(name, request):
    team = STATE["data"]["teams"].get(request["team"])
    if team is None or name not in team["invites"]:
        raise Refused("you were not invited to that team")
    owner = team["owner"]
    answer = dict(team["invites"][name])
    answer["owner"] = owner
    answer["owner_rsa_public_key"] = STATE["data"]["users"][owner]["rsa_public_key"]
    return answer


# The server checks that the client belongs to the team. This is what stops someone
# that is registered but not in the team from sending or getting the team's data.
def check_member(name, team_name):
    team = STATE["data"]["teams"].get(team_name)
    if team is None or name not in team["members"]:
        raise Refused("you are not a member of that team")


# ---------- STEP 7: the server takes the data, scores it, and signs the verdict ----------

# Scores a row using the columns left readable (the server can't read the encrypted ones).
# This is just a few simple rules that add up points, not a trained model.
def score(row):
    points = 0
    if row.get("install_script_added") == "True": points += 3
    if row.get("has_preinstall") == "True": points += 2
    if row.get("has_postinstall") == "True": points += 2
    if row.get("publisher_changed") == "True": points += 2
    if row.get("found_on_github") == "False": points += 2
    if row.get("uses_child_process") == "True": points += 1
    if row.get("uses_eval") == "True": points += 1
    return points


# The exact text that is signed for a verdict (the row id and the verdict together).
def verdict_text(row_id, verdict):
    return (row_id + "|" + verdict).encode()


# The server takes the protected rows, scores the data as suspicious or not flagged, and
# stores that verdict and signs it with its own private key so that a team member can
# fetch it later (and can check it really came from the server).
def send(name, request):
    check_member(name, request["team"])
    verdicts = []
    for row in request["rows"]:
        verdict = "suspicious" if score(row) >= 4 else "not flagged"
        signature = crypto.rsa_sign(STATE["private_key"], verdict_text(row["row_id"], verdict))
        STATE["data"]["rows"][request["team"]][row["row_id"]] = {
            "row": row, "sender": name, "verdict": verdict, "signature": signature,
        }
        verdicts.append({"row_id": row["row_id"], "verdict": verdict, "signature": signature})
    save()
    return {"verdicts": verdicts}


# ---------- STEP 8: a team member fetches the data ----------

# The server checks the team member's signature (done in message above) and that they
# belong to the team before sending the rows and verdicts.
def fetch(name, request):
    check_member(name, request["team"])
    return {"rows": list(STATE["data"]["rows"][request["team"]].values())}


# ---------- the part that receives the requests ----------

class Handler(BaseHTTPRequestHandler):
    # Every request from a client comes in here. It reads the JSON that was sent, gives
    # it to the right function (register, hello or message), and sends the answer back.
    # If something is refused, the reason is sent back instead.
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        addresses = {"/register": register, "/hello": hello, "/message": message}
        try:
            body = json.loads(self.rfile.read(length))
            if self.path not in addresses:
                raise Refused("unknown address")
            status, answer = 200, addresses[self.path](body)
        except Refused as error:
            status, answer = 400, {"error": str(error)}
        except (KeyError, ValueError, TypeError):
            status, answer = 400, {"error": "badly formed request"}

        data = json.dumps(answer).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # Prints one short line for each request (never the message itself or any keys).
    def log_message(self, format, *args):
        print("request:", self.path, "->", args[1] if len(args) > 1 else "")


# Starts the server, and it keeps running until it is stopped with Ctrl+C.
def run(port=8000):
    load()
    server = HTTPServer(("127.0.0.1", port), Handler)
    print(f"Server running on http://127.0.0.1:{port}  (Ctrl+C to stop)")
    server.serve_forever()


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "keygen":
        keygen()
    elif command == "run":
        run(int(sys.argv[2]) if len(sys.argv) > 2 else 8000)
    else:
        print("usage: python server.py keygen | run [port]")
