from flask import Flask
import os

app = Flask(__name__)


@app.route("/")
def home():
    return """
    <h1>Admin Service</h1>
    <p>This service was started automatically by PortDock.</p>
    """


if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            8000
        )
    )

    print(
        f"Admin Service running on port {port}"
    )

    app.run(
        host="127.0.0.1",
        port=port
    )