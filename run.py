from flask import Flask, jsonify
from apps import blueprint

app = Flask(__name__)

# Register the blueprint
app.register_blueprint(blueprint)

@app.route('/')
def home():
    return jsonify({"message": "Welcome to the Flask OAuth2.0 Server!"})

if __name__ == '__main__':
    print("Starting the Flask OAuth2.0 Server...")
    print("Server running on http://localhost:5000")
    print("Use Postman to test the API endpoints.")
    app.run(debug=True)
