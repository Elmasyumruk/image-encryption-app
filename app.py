"""
Image Encryption Application (IEA) - Main Server
CMSE-456 / CMPE-455 Term Project
"""
import os
import json
import base64
import threading
import time
from flask import Flask, render_template, request, session, redirect, url_for, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename

from database import (init_db, create_user, verify_user, get_user,
                      save_rsa_key, get_active_rsa_key, get_all_rsa_keys, get_all_rsa_keys_table,
                      save_message, get_messages, log_activity, get_all_users,
                      get_activity_log, get_activity_log_count, get_all_messages, get_message_count)
from crypto_utils import (generate_rsa_keypair, generate_des_key, des_encrypt, des_decrypt,
                           rsa_encrypt, rsa_decrypt, sign_data, verify_signature, b64e, b64d)

app = Flask(__name__)
app.secret_key = os.urandom(32)
app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(__file__), "uploads")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB

socketio = SocketIO(app, cors_allowed_origins="*")

# In-memory: username -> socket session id
connected_users = {}

# Server RSA key pair (for session key exchange with clients)
# Rotated periodically
SERVER_PRIVATE_KEY = None
SERVER_PUBLIC_KEY = None
KEY_ROTATION_INTERVAL = 60  # seconds


def rotate_server_keys():
    global SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY
    while True:
        SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY = generate_rsa_keypair()
        log_activity("server", "RSA_KEY_ROTATION", "Server RSA keys rotated")
        # Notify all connected clients about new server public key
        socketio.emit("server_pubkey", {"public_key": SERVER_PUBLIC_KEY})
        time.sleep(KEY_ROTATION_INTERVAL)


# Start key rotation thread
key_rotation_thread = threading.Thread(target=rotate_server_keys, daemon=True)
key_rotation_thread.start()


# ─────────────────────────────────────────────
#  HTTP Routes
# ─────────────────────────────────────────────

@app.route("/")
def index():
    if "username" in session:
        if session.get("role") == "sysadmin":
            return redirect(url_for("admin"))
        return redirect(url_for("chat"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        user = verify_user(username, password)
        if user:
            session["username"] = username
            session["role"] = user["role"]
            log_activity(username, "LOGIN", f"IP: {request.remote_addr}", request.remote_addr)
            from datetime import datetime
            socketio.emit("admin_activity_update", {
                "username": username, "action": "LOGIN",
                "details": f"IP: {request.remote_addr}",
                "ip": request.remote_addr,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }, room="sysadmin")
            if user["role"] == "sysadmin":
                return redirect(url_for("admin"))
            return redirect(url_for("chat"))
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if not username or not password:
            return render_template("register.html", error="All fields required")
        ok = create_user(username, password)
        if not ok:
            return render_template("register.html", error="Username already taken")
        log_activity(username, "REGISTER", f"IP: {request.remote_addr}", request.remote_addr)
        from datetime import datetime
        socketio.emit("admin_activity_update", {
            "username": username, "action": "REGISTER",
            "details": f"IP: {request.remote_addr}",
            "ip": request.remote_addr,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }, room="sysadmin")
        session["username"] = username
        session["role"] = "client"
        return redirect(url_for("chat"))
    return render_template("register.html")


@app.route("/logout")
def logout():
    username = session.get("username")
    if username:
        log_activity(username, "LOGOUT")
        from datetime import datetime
        socketio.emit("admin_activity_update", {
            "username": username, "action": "LOGOUT",
            "details": "User logged out",
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }, room="sysadmin")
    session.clear()
    return redirect(url_for("login"))


@app.route("/chat")
def chat():
    if "username" not in session or session.get("role") == "sysadmin":
        return redirect(url_for("login"))
    users = get_all_users()
    other_users = [u for u in users if u["username"] != session["username"]]
    return render_template("chat.html",
                           username=session["username"],
                           users=other_users,
                           server_pubkey=SERVER_PUBLIC_KEY)


@app.route("/admin")
def admin():
    if session.get("role") != "sysadmin":
        return redirect(url_for("login"))
    users = get_all_users()
    logs = get_activity_log(50)
    log_count = get_activity_log_count()
    messages = get_all_messages(30)
    message_count = get_message_count()
    rsa_keys = get_all_rsa_keys_table()
    online = list(connected_users.keys())
    return render_template("admin.html",
                           users=users,
                           logs=logs,
                           log_count=log_count,
                           messages=messages,
                           message_count=message_count,
                           rsa_keys=rsa_keys,
                           online=online,
                           server_pubkey=SERVER_PUBLIC_KEY)




@app.route("/api/server_pubkey")
def api_server_pubkey():
    return jsonify({"public_key": SERVER_PUBLIC_KEY})


@app.route("/api/encrypted_image/<filename>")
def api_encrypted_image(filename):
    """Serve the encrypted image bytes as base64 so the client can decrypt them."""
    if "username" not in session:
        return jsonify({"error": "unauthorized"}), 401
    safe = secure_filename(filename)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], safe)
    if not os.path.exists(filepath):
        return jsonify({"error": "not found"}), 404
    with open(filepath, "rb") as f:
        data = f.read()
    import base64
    return jsonify({"data": base64.b64encode(data).decode()})


@app.route("/api/user_pubkey/<username>")
def api_user_pubkey(username):
    """Return the active RSA public key for a user (for encrypting session keys to them)."""
    if "username" not in session:
        return jsonify({"error": "unauthorized"}), 401
    key = get_active_rsa_key(username)
    if not key:
        return jsonify({"username": username, "public_key": None})
    return jsonify({"username": username, "public_key": key["public_key"]})


@app.route("/api/my_keys")
def api_my_keys():
    """Return ALL RSA keypairs (current + historical) for the logged-in user.
       Client uses these private keys to decrypt message history."""
    if "username" not in session:
        return jsonify([])
    keys = get_all_rsa_keys(session["username"])
    return jsonify(keys)


@app.route("/api/messages")
def api_messages():
    if "username" not in session:
        return jsonify([])
    me = session["username"]
    msgs = get_messages(me)
    # For each message, give the requester the session key they can decrypt:
    # - if I'm the receiver → use encrypted_session_key (encrypted with my pubkey)
    # - if I'm the sender   → use encrypted_session_key_sender (encrypted with my pubkey)
    result = []
    for m in msgs:
        if m["sender"] == me:
            m["encrypted_session_key"] = m.get("encrypted_session_key_sender") or m.get("encrypted_session_key")
        result.append(m)
    return jsonify(result)


# ─────────────────────────────────────────────
#  Socket.IO Events
# ─────────────────────────────────────────────

@socketio.on("connect")
def on_connect():
    if "username" not in session:
        return False
    username = session["username"]
    connected_users[username] = request.sid
    join_room(username)
    log_activity(username, "SOCKET_CONNECT", f"SID: {request.sid}")
    emit("server_pubkey", {"public_key": SERVER_PUBLIC_KEY})
    socketio.emit("user_status", {"username": username, "status": "online"}, room="sysadmin")
    emit("connected_users", {"users": list(connected_users.keys())}, broadcast=True)
    # Broadcast full user list so all clients and admin can update in real-time
    all_users = [{"username": u["username"]} for u in get_all_users()]
    socketio.emit("users_updated", {
        "users": all_users,
        "online": list(connected_users.keys())
    })


@socketio.on("disconnect")
def on_disconnect():
    username = session.get("username")
    if username and username in connected_users:
        del connected_users[username]
        log_activity(username, "SOCKET_DISCONNECT")
        socketio.emit("user_status", {"username": username, "status": "offline"}, room="sysadmin")
        emit("connected_users", {"users": list(connected_users.keys())}, broadcast=True)


@socketio.on("join_admin")
def on_join_admin():
    if session.get("role") == "sysadmin":
        join_room("sysadmin")





@socketio.on("update_pubkey")
def on_update_pubkey(data):
    """Client pushes new RSA keypair (public + private) after generating or rotating keys.
       Both are stored in rsa_keys table so history is always decryptable."""
    username = session.get("username")
    if not username or "pub_key" not in data or "priv_key" not in data:
        return
    save_rsa_key(username, data["pub_key"], data["priv_key"])
    log_activity(username, "RSA_KEY_ROTATION", "Client RSA keys saved to DB")
    for other, sid in connected_users.items():
        if other != username:
            socketio.emit("peer_key_updated", {"username": username}, to=sid)
    from datetime import datetime
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    socketio.emit("admin_activity_update", {
        "username": username, "action": "RSA_KEY_ROTATION",
        "details": "Client RSA keys rotated", "created_at": now
    }, room="sysadmin")
    # Live update admin RSA keys panel
    key = get_active_rsa_key(username)
    if key:
        socketio.emit("admin_rsa_update", {
            "id": key["id"], "username": username,
            "is_active": 1, "created_at": key["created_at"],
            "pub_preview": key["public_key"][:60]
        }, room="sysadmin")


@socketio.on("send_text")
def on_send_text(data):
    """
    Client sends an encrypted text message.
    data: { receiver, encrypted_message, signature }
    The message content is DES-encrypted with a session key.
    The session key is RSA-encrypted with receiver's public key.
    """
    sender = session.get("username")
    if not sender:
        return
    receiver = data.get("receiver")
    if not receiver:
        return

    save_message(
        sender=sender,
        receiver=receiver,
        msg_type="text",
        content=data.get("encrypted_message"),
        signature=data.get("signature"),
        enc_session_key=data.get("encrypted_session_key"),
        enc_session_key_sender=data.get("encrypted_session_key_sender")
    )
    log_activity(sender, "SEND_TEXT", f"To: {receiver}")
    from datetime import datetime
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    enc_content = data.get("encrypted_message", "")
    socketio.emit("admin_message_update", {
        "sender": sender, "receiver": receiver, "type": "text",
        "created_at": now, "signed": bool(data.get("signature")),
        "content": enc_content[:80] + ("…" if len(enc_content) > 80 else "")
    }, room="sysadmin")
    socketio.emit("admin_activity_update", {
        "username": sender, "action": "SEND_TEXT",
        "details": f"To: {receiver}", "created_at": now
    }, room="sysadmin")

    # Forward to receiver if online
    payload = {
        "sender": sender,
        "receiver": receiver,
        "encrypted_message": data.get("encrypted_message"),
        "encrypted_session_key": data.get("encrypted_session_key"),
        "signature": data.get("signature"),
        "type": "text"
    }
    if receiver in connected_users:
        socketio.emit("receive_message", payload, to=connected_users[receiver])


@socketio.on("send_image")
def on_send_image(data):
    """
    Client sends a DES-encrypted image.
    data: { receiver, encrypted_image_b64, encrypted_session_key, signature, filename }
    """
    sender = session.get("username")
    if not sender:
        return
    receiver = data.get("receiver")
    if not receiver:
        return

    # Save encrypted image to disk
    enc_image_bytes = b64d(data.get("encrypted_image_b64", ""))
    filename = secure_filename(f"{sender}_to_{receiver}_{int(time.time())}.enc")
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    with open(filepath, "wb") as f:
        f.write(enc_image_bytes)

    save_message(
        sender=sender,
        receiver=receiver,
        msg_type="image",
        image_path=filename,
        signature=data.get("signature"),
        enc_session_key=data.get("encrypted_session_key"),
        enc_session_key_sender=data.get("encrypted_session_key_sender")
    )
    log_activity(sender, "SEND_IMAGE", f"To: {receiver}, file: {filename}")
    from datetime import datetime
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    socketio.emit("admin_message_update", {
        "sender": sender, "receiver": receiver, "type": "image",
        "created_at": now, "signed": bool(data.get("signature")),
        "content": filename
    }, room="sysadmin")
    socketio.emit("admin_activity_update", {
        "username": sender, "action": "SEND_IMAGE",
        "details": f"To: {receiver}", "created_at": now
    }, room="sysadmin")

    payload = {
        "sender": sender,
        "receiver": receiver,
        "encrypted_image_b64": data.get("encrypted_image_b64"),
        "encrypted_session_key": data.get("encrypted_session_key"),
        "signature": data.get("signature"),
        "filename": filename,
        "type": "image"
    }
    if receiver in connected_users:
        socketio.emit("receive_message", payload, to=connected_users[receiver])


if __name__ == "__main__":
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    init_db()

    ssl_ctx = None
    cert_file = os.path.join(os.path.dirname(__file__), "cert.pem")
    key_file  = os.path.join(os.path.dirname(__file__), "key.pem")
    if os.path.exists(cert_file) and os.path.exists(key_file):
        import ssl
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(cert_file, key_file)
        proto = "https"
    else:
        proto = "http"

    import socket as _socket
    local_ip = _socket.gethostbyname(_socket.gethostname())
    print("=== Image Encryption Application (IEA) ===")
    print(f"Local:   {proto}://localhost:5000")
    print(f"Network: {proto}://{local_ip}:5000")
    print("Admin login: admin / admin123")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False,
                 allow_unsafe_werkzeug=True, ssl_context=ssl_ctx)
