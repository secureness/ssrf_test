from itertools import count
import time
import flask
from flask import request
from flask import Response
import requests

app = flask.Flask(__name__.split('.')[0])

@app.route("/ssrf",methods = ['HEAD','POST', 'GET'])
def ssrf():
    url = request.args.get('url2')
    if not url:
        url = "http://127.0.0.1:8080/test"
    response = requests.get(url)
    return response

@app.route("/test",methods = ['HEAD','POST', 'GET'])
def test():
    return "test test test"

if __name__ == "__main__":
    #app.run(ssl_context=('cert.pem', 'key.pem'))
    app.run(debug=False)
