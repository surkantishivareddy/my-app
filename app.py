from flask import Flask, request, redirect, session, url_for
import os, secrets, requests, base64

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")

CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID")
CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET")

@app.route("/")
def home():
    return '<a href="/login">Login with GitHub</a>'

@app.route("/login")
def login():
    state = secrets.token_urlsafe(16)
    session["oauth_state"] = state
    authorize_url = (
        "https://github.com/login/oauth/authorize"
        f"?client_id={CLIENT_ID}"
        f"&scope=repo"
        f"&state={state}"
    )
    return redirect(authorize_url)

@app.route("/callback")
def callback():
    state = request.args.get("state")
    if not state or state != session.get("oauth_state"):
        return "State mismatch. Try logging in again.", 400

    code = request.args.get("code")
    if not code:
        return "Missing code from GitHub.", 400

    token_res = requests.post(
        "https://github.com/login/oauth/access_token",
        headers={"Accept": "application/json"},
        data={"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "code": code},
        timeout=20,
    )
    token_json = token_res.json()
    if "access_token" not in token_json:
        return f"OAuth error: {token_json}", 400

    session["token"] = token_json["access_token"]
    return redirect(url_for("upload_page"))

@app.route("/upload_page")
def upload_page():
    return """
    <h2>Upload File to Your GitHub Repo</h2>
    <form action="/upload" method="post" enctype="multipart/form-data">
        <label>Repo (username/repo):</label>
        <input name="repo_name" required />
        <br/><br/>
        <input type="file" name="file" required />
        <br/><br/>
        <button type="submit">Upload</button>
    </form>
    """

@app.route("/upload", methods=["POST"])
def upload():
    token = session.get("token")
    if not token:
        return redirect(url_for("home"))

    repo = request.form["repo_name"].strip()
    file = request.files["file"]
    filename = file.filename
    content_b64 = base64.b64encode(file.read()).decode()

    url = f"https://api.github.com/repos/{repo}/contents/{filename}"
    headers = {"Authorization": f"token {token}"}
    data = {"message": f"Add {filename} via Git Helper", "content": content_b64}
    r = requests.put(url, json=data, headers=headers, timeout=30)

    if r.status_code == 422 and "sha" not in data:
        meta = requests.get(url, headers=headers).json()
        sha = meta.get("sha")
        if sha:
            data["sha"] = sha
            r = requests.put(url, json=data, headers=headers, timeout=30)

    if r.status_code in (200, 201):
        return f"✅ Uploaded! <a href='https://github.com/{repo}'>Open repo</a>"
    return f"❌ Error: {r.status_code} {r.text}"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
