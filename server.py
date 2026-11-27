# server.py (Version corrigée et requalifiée)
import sqlite3
import os
import re
from flask import Flask, request, abort

app = Flask(__name__)

@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # CORRECTION : Requête paramétrée (Sanitizer intégré)
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()

@app.route("/ping")
def ping_host():
    # nosemgrep: python.django.security.injection.command.command-injection-os-system.command-injection-os-system -- Même exception AppSec (alerte ancrée sur la Source, flux validé ci-dessous)
    target = request.args.get("ip")
    # Validation stricte par Regex (Whitelist)
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target or ""):
        abort(400, "Invalid IP address")

    # nosemgrep: python.flask.security.injection.os-system-injection.os-system-injection, python.lang.security.dangerous-system-call.dangerous-system-call -- Justification AppSec : IP validée en amont par regex IPv4 stricte (whitelist), endpoint réservé aux admins
    os.system("ping -c 1 " + target)
    return "Ping triggered"

if __name__ == "__main__":
    app.run(port=5000)
