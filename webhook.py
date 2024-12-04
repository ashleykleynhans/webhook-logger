#!/usr/bin/env python3
import io
import argparse
import json
import uuid
import base64
from PIL import Image
from flask import Flask, request, jsonify, make_response
from werkzeug.serving import WSGIRequestHandler


OUTPUT_FORMAT = 'JPEG'


def get_args():
    parser = argparse.ArgumentParser(
        description='Webhook Payload logger'
    )

    parser.add_argument(
        '-p', '--port',
        help='Port to listen on',
        type=int,
        default=8090
    )

    parser.add_argument(
        '-H', '--host',
        help='Host to bind to',
        default='0.0.0.0'
    )

    return parser.parse_args()


def save_result_images(resp_json):
    for output_image in resp_json['output']['images']:
        img = Image.open(io.BytesIO(base64.b64decode(output_image)))
        file_extension = 'jpeg' if OUTPUT_FORMAT == 'JPEG' else 'png'
        output_file = f'{uuid.uuid4()}.{file_extension}'

        with open(output_file, 'wb') as f:
            print(f'Saving image: {output_file}')
            img.save(f, format=OUTPUT_FORMAT)


def save_result_image(resp_json):
    output_image = resp_json['output']['image']
    img = Image.open(io.BytesIO(base64.b64decode(output_image)))
    file_extension = 'jpeg' if OUTPUT_FORMAT == 'JPEG' else 'png'
    output_file = f'{uuid.uuid4()}.{file_extension}'

    with open(output_file, 'wb') as f:
        print(f'Saving image: {output_file}')
        img.save(f, format=OUTPUT_FORMAT)


WSGIRequestHandler.server_version = 'WebhookLogger/1.0'
WSGIRequestHandler.sys_version = ''
app = Flask(__name__)


@app.before_request
def before_request():
    # Only handle POST requests to /
    if request.method == 'POST' and request.path == '/':
        content_type = request.headers.get('Content-Type', '')

        # If Content-Type is not set or is not application/json
        if 'application/json' not in content_type.lower():
            # Try to parse the data as JSON
            try:
                # Force Flask to parse JSON data even if Content-Type is not set
                if request.data:
                    request.get_json(force=True)
                # Modify the request headers to include Content-Type
                request.environ['CONTENT_TYPE'] = 'application/json'
            except Exception as e:
                # If JSON parsing fails, return 400 Bad Request
                return make_response(jsonify({
                    'status': 'error',
                    'msg': 'Invalid JSON data',
                    'detail': str(e)
                }), 400)


@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify(
        {
            'status': 'error',
            'msg': f'{request.url} not found',
            'detail': str(error)
        }
    ), 404)


@app.errorhandler(500)
def internal_server_error(error):
    return make_response(jsonify(
        {
            'status': 'error',
            'msg': 'Internal Server Error',
            'detail': str(error)
        }
    ), 500)


@app.route('/')
def ping():
    return make_response(jsonify(
        {
            'status': 'ok'
        }
    ), 200)


@app.route('/', methods=['POST'])
def webhook_handler():
    token = request.args.get('token', '-')
    print('Token: ' + token)
    print('User agent: ' + request.headers.get('user-agent', '-'))

    payload = request.get_json()

    if 'output' in payload and 'images' in payload['output']:
        save_result_images(payload)
    elif 'output' in payload and 'image' in payload['output']:
        save_result_image(payload)
    else:
        print(json.dumps(payload, indent=4, default=str))

    return make_response(jsonify(
        {
            'status': 'ok'
        }
    ), 200)


if __name__ == '__main__':
    args = get_args()
    app.run(host=args.host, port=args.port)
