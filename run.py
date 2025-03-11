from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(
        host="localhost",
        port=5000,
        debug=True,
        # ssl_context=(app.config.SSL_CERT, app.config.SSL_KEY),
    )
