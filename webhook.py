#!/usr/bin/env python3
import os
import sys
import io
import argparse
import json
import uuid
import base64
import hashlib
import requests
import math
from Crypto.Cipher import AES
from PIL import Image
from dotenv import dotenv_values
from flask import Flask, request, jsonify, make_response
from werkzeug.serving import WSGIRequestHandler


OUTPUT_FORMAT = 'JPEG'


def load_env_variables():
    """Load environment variables from .env file."""
    script_path = os.path.abspath(sys.argv[0])
    return dotenv_values(os.path.dirname(script_path) + '/.env')


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


def generate_msg_signature(client_id, timestamp, nonce, msg_encrypt):
    # Convert all values to strings - timestamp is numeric in the payload
    sorted_str = ''.join(sorted([str(client_id), str(timestamp), str(nonce), str(msg_encrypt)]))
    hash_value = hashlib.sha1(sorted_str.encode('utf-8')).hexdigest()
    return hash_value


def generate_aes_decrypt(data_encrypt, client_id, client_secret):
    aes_key = client_secret.encode('utf-8')

    # Ensure the IV is 16 bytes long
    iv = client_id.encode('utf-8')
    iv = iv[:16] if len(iv) >= 16 else iv.ljust(16, b'\0')

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(base64.b64decode(data_encrypt))

    padding_len = decrypted_data[-1]
    return decrypted_data[:-padding_len].decode('utf-8')

def decrypt_akool_webhook(payload):
    print('Decrypting Akool webhook payload...')
    env = load_env_variables()
    client_id = env.get('AKOOL_CLIENT_ID', None)
    client_secret = env.get('AKOOL_CLIENT_SECRET', None)

    if not client_id or not client_secret:
        print('AKOOL_CLIENT_ID or AKOOL_CLIENT_SECRET not set in .env file')
        return

    signature = payload.get('signature')
    timestamp = payload.get('timestamp')
    nonce = payload.get('nonce')
    data_encrypt = payload.get('dataEncrypt')

    if not signature or not timestamp or not nonce or not data_encrypt:
        print('Missing required fields in payload for decryption')
        return

    expected_signature = generate_msg_signature(client_id, timestamp, nonce, data_encrypt)

    if signature != expected_signature:
        print('Invalid signature. Payload may have been tampered with.')
        return

    try:
        decrypted_json_str = generate_aes_decrypt(data_encrypt, client_id, client_secret)
        decrypted_payload = json.loads(decrypted_json_str)

        id = decrypted_payload.get('_id')
        status = decrypted_payload.get('status', 0)
        type = decrypted_payload.get('type')
        url = decrypted_payload.get('url')
        deduction_credit = decrypted_payload.get('deduction_credit')

        if id and status == 2:
            print(f"{type} is in progress - deduction credit: {deduction_credit}...")
        elif id and status == 3:
            print(f"{type} completed successfully - deduction credit: {deduction_credit}")
            if url:
                print(f"Result URL: {url}")
                # Download the image from the URL and save it
                try:
                    response = requests.get(url)
                    response.raise_for_status()
                    img = Image.open(io.BytesIO(response.content))
                    file_extension = 'jpeg' if OUTPUT_FORMAT == 'JPEG' else 'png'
                    output_file = f'{uuid.uuid4()}.{file_extension}'

                    # Save the image to disk
                    with open(output_file, 'wb') as f:
                        print(f'Saving image: {output_file}')
                        img.save(f, format=OUTPUT_FORMAT)

                except requests.exceptions.RequestException as e:
                    print(f'Error downloading image from URL: {e}')
                except Exception as e:
                    print(f'Error processing/saving image: {e}')
        else:
            print(json.dumps(decrypted_payload, indent=4, default=str))

    except Exception as e:
        print(f'Error during decryption or processing: {e}')


def get_aspect_ratio(img):
    width, height = img.size

    # Required aspect ratios with their decimal values
    common_ratios = [
        (1, 1, 1.0),        # 1:1 Square
        (2, 3, 0.6667),     # 2:3 Portrait
        (3, 2, 1.5),        # 3:2 Landscape
        (3, 4, 0.75),       # 3:4 Portrait
        (4, 3, 1.3333),     # 4:3 Landscape
        (9, 16, 0.5625),    # 9:16 Portrait (vertical video)
        (16, 9, 1.7778),    # 16:9 Landscape (widescreen)
        (21, 9, 2.3333),    # 21:9 Landscape (ultrawide)
    ]

    # Calculate actual ratio
    actual_ratio = width / height

    # Find closest common ratio (with 3% tolerance)
    tolerance = 0.03
    for w, h, target in common_ratios:
        if abs(actual_ratio - target) < tolerance:
            return width, height, w, h

    # If no common ratio matches, return None or the actual ratio
    return width, height, None, None

def save_result_images(resp_json):
    for output_image in resp_json['output']['images']:
        img = Image.open(io.BytesIO(base64.b64decode(output_image)))
        file_extension = 'jpeg' if OUTPUT_FORMAT == 'JPEG' else 'png'
        output_file = f'{uuid.uuid4()}.{file_extension}'

        with open(output_file, 'wb') as f:
            width, height, ratio_width, ratio_height = get_aspect_ratio(img)
            print(f'Image dimensions: {width}x{height}')
            print(f'Image Aspect Ratio: {ratio_width}:{ratio_height}')
            print(f'Saving image: {output_file}')
            img.save(f, format=OUTPUT_FORMAT)


def save_result_image(resp_json):
    output = resp_json.get('output', {})

    if 'result_image' in output:
        output_image = output['result_image']
    elif 'image' in output:
        output_image = output['image']

    img = Image.open(io.BytesIO(base64.b64decode(output_image)))
    file_extension = 'jpeg' if OUTPUT_FORMAT == 'JPEG' else 'png'
    output_file = f'{uuid.uuid4()}.{file_extension}'

    with open(output_file, 'wb') as f:
        width, height, ratio_width, ratio_height = get_aspect_ratio(img)
        print(f'Image dimensions: {width}x{height}')
        print(f'Image Aspect Ratio: {ratio_width}:{ratio_height}')
        print(f'Saving image: {output_file}')
        img.save(f, format=OUTPUT_FORMAT)


def save_openai_result_images(resp_json):
    for output_image in resp_json['output']['data']:
        output_image = output_image.get('b64_json')
        img = Image.open(io.BytesIO(base64.b64decode(output_image)))
        file_extension = 'jpeg' if OUTPUT_FORMAT == 'JPEG' else 'png'
        output_file = f'{uuid.uuid4()}.{file_extension}'

        with open(output_file, 'wb') as f:
            width, height, ratio_width, ratio_height = get_aspect_ratio(img)
            print(f'Image dimensions: {width}x{height}')
            print(f'Image Aspect Ratio: {ratio_width}:{ratio_height}')
            print(f'Saving image: {output_file}')
            img.save(f, format=OUTPUT_FORMAT)


def format_time_ms(milliseconds):
    """
    Convert milliseconds to human-readable format.

    Args:
        milliseconds (int/float): Time in milliseconds

    Returns:
        str: Formatted time string (e.g., "0.03s", "21.29s", "1m 42s")
    """
    if milliseconds is None:
        return '0s'

    # Convert to seconds
    total_seconds = milliseconds / 1000

    # Less than 1 minute
    if total_seconds < 60:
        # Format with 2 decimal places, then clean up
        if total_seconds == int(total_seconds):
            return f'{int(total_seconds)}s'
        else:
            # Show up to 2 decimal places, removing trailing zeros
            return f'{total_seconds:.2f}s'.rstrip('0').rstrip('.')

    # 1 minute or more
    minutes = int(total_seconds // 60)
    remaining_seconds = total_seconds % 60

    # Round seconds to nearest whole number for minute display
    remaining_seconds = round(remaining_seconds)

    # Handle case where rounding pushes seconds to 60
    if remaining_seconds == 60:
        minutes += 1
        remaining_seconds = 0

    if remaining_seconds == 0:
        return f'{minutes}m'
    else:
        return f'{minutes}m {remaining_seconds}s'


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
    job_id = payload.get('id')
    processor = payload.get('processor')
    delay_time = payload.get('delayTime')
    execution_time = payload.get('executionTime')

    if job_id:
        print(f'Job ID: {job_id}')

    if processor:
        print(f'Processor: {processor}')

    if delay_time:
        delay_formatted = format_time_ms(delay_time)
        print(f'Delay time: {delay_formatted}')

    if execution_time:
        execution_formatted = format_time_ms(execution_time)
        print(f'Execution time: {execution_formatted}')

    # if 'output' in payload:
    #     del payload['output']
    if 'output' in payload and 'images' in payload['output']:
        save_result_images(payload)
    elif 'output' in payload and 'image' in payload['output']:
        save_result_image(payload)
    elif 'output' in payload and 'data' in payload['output']:
        # del payload['output']['data']
        #print(json.dumps(payload, indent=4, default=str))
        save_openai_result_images(payload)
    elif 'output' in payload and 'result_image' in payload['output']:
        save_result_image(payload)
    elif 'signature' in payload and 'dataEncrypt' in payload and 'nonce' in payload:
        decrypt_akool_webhook(payload)
    else:
        print(json.dumps(payload, indent=4, default=str))

    if 'metadata' in payload:
        metadata = payload.get('metadata')
        print('Meta-data:', json.dumps(metadata, indent=4, default=str))

    print('-' * 50)

    return make_response(jsonify(
        {
            'status': 'ok'
        }
    ), 200)


if __name__ == '__main__':
    args = get_args()
    app.run(host=args.host, port=args.port)
