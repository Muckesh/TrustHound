"""
ShopMart — deliberately vulnerable demo web app.

DO NOT deploy this anywhere but an isolated lab you own. The /products
endpoint builds SQL by raw string concatenation on purpose, and the
database role it connects as has EXECUTE on every function in the
public schema (including the pgsql-http extension's http()/http_get()
functions) on purpose. This is the whole point of the lab: a classic
SQL injection that a scanner/agent has to recognize can be escalated,
via the database engine's own outbound-HTTP capability, into an SSRF
against the EC2 instance metadata service — no separate app-level
"fetch a URL" feature required.
"""
import os

import psycopg2
from flask import Flask, render_template_string, request

app = Flask(__name__)

DB_HOST = os.environ.get("DB_HOST", "db")
DB_NAME = os.environ.get("DB_NAME", "shopdb")
DB_USER = os.environ.get("DB_USER", "appuser")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "appuserpassword")


def get_conn():
    return psycopg2.connect(
        host=DB_HOST, dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD
    )


PAGE = """
<!doctype html>
<html>
<head>
  <title>ShopMart</title>
  <style>
    body { font-family: sans-serif; max-width: 720px; margin: 40px auto; }
    input[type=text] { width: 320px; padding: 6px; }
    table { border-collapse: collapse; width: 100%; margin-top: 16px; }
    td, th { border: 1px solid #ccc; padding: 8px; text-align: left; word-break: break-word; }
    .err { color: #b00020; }
  </style>
</head>
<body>
  <h1>ShopMart product search</h1>
  <form method="get" action="/products">
    <label>Category: </label>
    <input type="text" name="category" value="{{ category }}">
    <button type="submit">Search</button>
  </form>
  {% if error %}<p class="err">Error: {{ error }}</p>{% endif %}
  <table>
    <tr><th>ID</th><th>Name</th><th>Price</th></tr>
    {% for row in rows %}
    <tr><td>{{ row[0] }}</td><td>{{ row[1] }}</td><td>{{ row[2] }}</td></tr>
    {% endfor %}
  </table>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(PAGE, category="", rows=[], error=None)


@app.route("/products")
def products():
    category = request.args.get("category", "")

    # VULNERABLE ON PURPOSE: raw string concatenation into SQL, no
    # parameterized query, no input validation, no allowlist. This is
    # the injection point for the whole lab. Never write real code
    # like this.
    query = "SELECT id, name, price FROM products WHERE category = '" + category + "'"

    rows, error = [], None
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(query)
            rows = cur.fetchall()
    except Exception as e:  # deliberately verbose error reporting, also on purpose
        error = str(e)
    finally:
        conn.close()

    return render_template_string(PAGE, category=category, rows=rows, error=error)


@app.route("/healthz")
def healthz():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
