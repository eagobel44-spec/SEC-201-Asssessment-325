# test_system.py
# Tests for the whole system. Run with:   python -m pytest test_system.py -q
#
# Each test starts a real server (on a free port) with its own temporary folders,
# so the tests never touch the real keys or data.
# There are three kinds of tests: the crypto on its own, the whole flow working,
# and the things that the system has to refuse (tampering, wrong keys, not in the team).

import csv
import json
import threading
from http.server import HTTPServer

import pytest

import client
import crypto
import protect
import server

ROWS = [
    {"package": "test-alpha", "version": "1.0.0", "publisher": "test-ann", "followers": "420",
     "real_name": "Ann Example", "tarball": "http://x/alpha-1.0.0.tgz", "attestations": "",
     "has_preinstall": "False", "install_script_added": "False", "label": "benign"},
    {"package": "test-alpha", "version": "1.0.1", "publisher": "test-bob", "followers": "0",
     "real_name": "", "tarball": "http://x/alpha-1.0.1.tgz", "attestations": "yes",
     "has_preinstall": "True", "install_script_added": "True", "label": "malicious"},
]


# Starts a server, and then alice (owner), bob (team member) and carol (not in the team)
# each generate their keys and register with it.
@pytest.fixture
def system(tmp_path, monkeypatch):
    monkeypatch.setattr(client, "HOME", str(tmp_path / "clients"))
    monkeypatch.setattr(server, "SERVER_DIR", str(tmp_path / "server"))
    monkeypatch.setattr("sys.argv", ["client.py", "--yes"])   # skip the y/n questions

    server.keygen()
    server.load()
    web = HTTPServer(("127.0.0.1", 0), server.Handler)
    threading.Thread(target=web.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{web.server_port}"
    key_file = str(tmp_path / "server" / "server_public.pem")

    dataset = tmp_path / "data.csv"
    with open(dataset, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(ROWS[0]))
        writer.writeheader()
        writer.writerows(ROWS)

    for name in ("alice", "bob", "carol"):
        client.keygen(name)
        client.register(name, url, key_file)

    class System:
        pass
    s = System()
    s.url, s.dataset, s.tmp = url, str(dataset), tmp_path
    s.data_file = tmp_path / "server" / "data.json"
    yield s
    web.shutdown()


# The owner creates the team and the two team keys, then the second diffie-hellman
# exchange happens: alice invites bob, and bob joins and decrypts the team keys.
def make_team(system):
    client.create_team("alice", "blue")
    client.invite("alice", "bob")
    client.join("bob", "blue")


# ---------- the crypto on its own ----------
# These check each function from crypto.py without a server.

def test_signature_verifies_and_detects_changes():
    key = crypto.rsa_generate()
    signature = crypto.rsa_sign(key, b"hello")
    assert crypto.rsa_verify(key.public_key(), b"hello", signature)
    assert not crypto.rsa_verify(key.public_key(), b"hellp", signature)                    # changed message
    assert not crypto.rsa_verify(crypto.rsa_generate().public_key(), b"hello", signature)  # other key


def test_diffie_hellman_gives_both_sides_the_same_key():
    a, b = crypto.dh_private_key(), crypto.dh_private_key()
    key_a = crypto.dh_shared_key(crypto.dh_public_key(b), a)
    key_b = crypto.dh_shared_key(crypto.dh_public_key(a), b)
    assert key_a == key_b and len(key_a) == 32


def test_diffie_hellman_refuses_a_weak_public_key():
    with pytest.raises(ValueError):
        crypto.dh_shared_key(1, crypto.dh_private_key())


def test_aes_gcm_round_trip_and_tamper_detection():
    key = crypto.new_key()
    encrypted = crypto.aes_encrypt(key, b"secret")
    assert crypto.aes_decrypt(key, encrypted) == b"secret"
    assert crypto.aes_encrypt(key, b"secret") != encrypted          # new nonce each time

    raw = bytearray(crypto.to_bytes(encrypted))
    raw[15] ^= 1                                                    # flip one bit
    with pytest.raises(ValueError):
        crypto.aes_decrypt(key, crypto.to_text(bytes(raw)))
    with pytest.raises(ValueError):
        crypto.aes_decrypt(crypto.new_key(), encrypted)             # wrong key


def test_pseudonym_is_repeatable_but_needs_the_key():
    key = crypto.new_key()
    assert crypto.pseudonym(key, "express") == crypto.pseudonym(key, "express")
    assert crypto.pseudonym(key, "express") != crypto.pseudonym(key, "expresss")
    assert crypto.pseudonym(key, "express") != crypto.pseudonym(crypto.new_key(), "express")


def test_protect_row_hides_removes_and_generalizes():
    hmac_key, column_key = crypto.new_key(), crypto.new_key()
    protected = protect.protect_row(ROWS[0], hmac_key, column_key)

    assert "real_name" not in protected and "label" not in protected       # removed
    assert "package" not in protected and "test-alpha" not in json.dumps(protected)
    assert protected["followers_range"] == "100-999"                        # generalized
    assert protected["has_attestations"] == "False"                         # boolean
    assert protected["version"] == "1.0.0"                                  # kept readable
    assert protect.unprotect_row(protected, column_key)["package"] == "test-alpha"


# ---------- the whole flow ----------
# The owner sends the protected dataset to the server, and the team member fetches it
# and decrypts the encrypted columns using the team keys.

def test_owner_sends_and_member_fetches(system, capsys):
    make_team(system)
    client.send("alice", system.dataset)
    capsys.readouterr()
    client.fetch("bob")
    output = capsys.readouterr().out

    assert "test-alpha" in output                    # bob decrypted the package name
    assert "suspicious" in output and "not flagged" in output
    assert "alice" in output                         # who sent it


def test_member_gets_the_same_team_keys_as_the_owner(system):
    make_team(system)
    assert client.load_team("alice") == client.load_team("bob")


def test_server_stores_nothing_it_can_read(system):
    make_team(system)
    client.send("alice", system.dataset)
    stored = system.data_file.read_text()

    for secret in ("test-alpha", "test-ann", "test-bob", "Ann Example", "alpha-1.0.0.tgz"):
        assert secret not in stored
    _, hmac_key, column_key = client.load_team("alice")
    assert crypto.to_text(hmac_key) not in stored and crypto.to_text(column_key) not in stored
    assert "PRIVATE KEY" not in stored
    assert "1.0.0" in stored                         # readable columns are there, as intended


# ---------- things that must be refused ----------
# These are the attacks. Each one has to be refused, either by the server or by the client.

def test_outsider_cannot_join_send_or_fetch(system):
    make_team(system)
    with pytest.raises(SystemExit, match="not invited"):
        client.join("carol", "blue")

    # carol pretends that she has team keys and asks the server anyway. The server still
    # refuses, since it checks that she belongs to the team.
    client.save_team("carol", "blue", crypto.new_key(), crypto.new_key())
    with pytest.raises(SystemExit, match="not a member"):
        client.fetch("carol")
    with pytest.raises(SystemExit, match="not a member"):
        client.send("carol", system.dataset)


def test_only_the_owner_can_invite(system):
    make_team(system)
    with pytest.raises(SystemExit, match="only the team owner"):
        client.invite("bob", "carol")


def test_unregistered_client_is_refused(system):
    client.keygen("dave")
    client.write("dave", "server_public.pem", client.read("alice", "server_public.pem"))
    client.write("dave", "server_url.txt", system.url)
    with pytest.raises(SystemExit, match="not registered"):
        client.connect("dave")


def test_registering_someone_elses_public_key_is_refused(system):
    alice_public = crypto.public_key_to_text(client.load_rsa("alice").public_key())
    mallory = crypto.rsa_generate()
    with pytest.raises(SystemExit, match="does not verify"):
        client.post(system.url + "/register", {
            "name": "mallory", "rsa_public_key": alice_public, "dh_public_key": "5",
            "rsa_signature": crypto.rsa_sign(mallory, alice_public.encode()),
            "dh_signature": crypto.rsa_sign(mallory, b"5"),
        })


def test_wrong_server_key_stops_the_client(system):
    fake = crypto.public_key_to_text(crypto.rsa_generate().public_key())
    client.write("alice", "server_public.pem", fake)
    with pytest.raises(SystemExit, match="not the trusted server"):
        client.connect("alice")


# This acts as a third party in the middle, that changes the messages passing through
# (either what the client sends, or what the server replies).
def tamper(monkeypatch, change_request=None, change_reply=None):
    real_post = client.post

    def post(url, body):
        if change_request:
            body = change_request(url, dict(body))
        reply = real_post(url, body)
        return change_reply(url, dict(reply)) if change_reply else reply

    monkeypatch.setattr(client, "post", post)


def test_man_in_the_middle_swapping_a_diffie_hellman_key_is_caught(system, monkeypatch):
    attacker_public = str(crypto.dh_public_key(crypto.dh_private_key()))

    def swap(url, reply):
        if url.endswith("/hello"):
            reply["dh_public_key"] = attacker_public
        return reply

    tamper(monkeypatch, change_reply=swap)
    with pytest.raises(SystemExit, match="not the trusted server"):
        client.connect("alice")


def test_tampered_message_is_refused_by_the_server(system, monkeypatch):
    def flip(url, body):
        if url.endswith("/message"):
            raw = bytearray(crypto.to_bytes(body["encrypted"]))
            raw[20] ^= 1
            body["encrypted"] = crypto.to_text(bytes(raw))
        return body

    tamper(monkeypatch, change_request=flip)
    with pytest.raises(SystemExit, match="signature does not verify"):
        client.create_team("alice", "blue")


def test_tampered_signature_is_refused_by_the_server(system, monkeypatch):
    def flip(url, body):
        if url.endswith("/message"):
            raw = bytearray(crypto.to_bytes(body["signature"]))
            raw[20] ^= 1
            body["signature"] = crypto.to_text(bytes(raw))
        return body

    tamper(monkeypatch, change_request=flip)
    with pytest.raises(SystemExit, match="signature does not verify"):
        client.create_team("alice", "blue")


def test_tampered_reply_is_caught_by_the_client(system, monkeypatch):
    def flip(url, reply):
        if url.endswith("/message"):
            raw = bytearray(crypto.to_bytes(reply["encrypted"]))
            raw[20] ^= 1
            reply["encrypted"] = crypto.to_text(bytes(raw))
        return reply

    tamper(monkeypatch, change_reply=flip)
    with pytest.raises(SystemExit, match="changed on the way"):
        client.create_team("alice", "blue")


def test_server_swapping_the_members_diffie_hellman_key_is_caught(system, monkeypatch):
    client.create_team("alice", "blue")
    real_message = client.message

    # The server gives alice its own diffie-hellman public key instead of bob's. The owner
    # checks bob's signature on it herself, so this is caught.
    def message(session, action, **fields):
        reply = real_message(session, action, **fields)
        if action == "get_user":
            reply["dh_public_key"] = str(crypto.dh_public_key(crypto.dh_private_key()))
        return reply

    monkeypatch.setattr(client, "message", message)
    with pytest.raises(SystemExit, match="not signed by bob"):
        client.invite("alice", "bob")


def test_changed_verdict_fails_its_signature(system):
    make_team(system)
    client.send("alice", system.dataset)
    session = client.connect("bob")
    item = client.message(session, "fetch", team="blue")["rows"][0]
    row_id = item["row"]["row_id"]

    assert client.verdict_is_genuine(session, row_id, item["verdict"], item["signature"])
    flipped = "not flagged" if item["verdict"] == "suspicious" else "suspicious"
    assert not client.verdict_is_genuine(session, row_id, flipped, item["signature"])
