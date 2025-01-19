from flask import Flask

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST', 'PUT', 'DELETE'])
def handle_request():
    return "Request successfully handled by the backend server!"

if __name__ == '__main__':
    app.run(port=5001)
