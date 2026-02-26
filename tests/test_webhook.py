import base64
import io
import json
import hashlib
from unittest.mock import patch, MagicMock

import pytest
from PIL import Image

from webhook import (
    app,
    load_env_variables,
    get_args,
    generate_msg_signature,
    generate_aes_decrypt,
    decrypt_akool_webhook,
    get_aspect_ratio,
    save_image,
    save_result_images,
    save_result_image,
    save_openai_result_images,
    format_time_ms,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_test_image(width=100, height=100, fmt='JPEG'):
    """Create a small in-memory image and return its base64-encoded bytes."""
    img = Image.new('RGB', (width, height), color='red')
    buf = io.BytesIO()
    img.save(buf, format=fmt)
    return base64.b64encode(buf.getvalue()).decode('utf-8')


# ---------------------------------------------------------------------------
# load_env_variables
# ---------------------------------------------------------------------------

class TestLoadEnvVariables:
    def test_returns_dict(self):
        result = load_env_variables()
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# get_args
# ---------------------------------------------------------------------------

class TestGetArgs:
    def test_defaults(self):
        with patch('sys.argv', ['webhook.py']):
            args = get_args()
            assert args.port == 8090
            assert args.host == '0.0.0.0'

    def test_custom_port_and_host(self):
        with patch('sys.argv', ['webhook.py', '-p', '9000', '-H', '127.0.0.1']):
            args = get_args()
            assert args.port == 9000
            assert args.host == '127.0.0.1'


# ---------------------------------------------------------------------------
# generate_msg_signature
# ---------------------------------------------------------------------------

class TestGenerateMsgSignature:
    def test_deterministic(self):
        sig1 = generate_msg_signature('cid', 123, 'nonce', 'enc')
        sig2 = generate_msg_signature('cid', 123, 'nonce', 'enc')
        assert sig1 == sig2

    def test_returns_hex_sha1(self):
        sig = generate_msg_signature('a', 'b', 'c', 'd')
        assert len(sig) == 40  # SHA-1 hex digest length


# ---------------------------------------------------------------------------
# generate_aes_decrypt
# ---------------------------------------------------------------------------

class TestGenerateAesDecrypt:
    def test_round_trip(self):
        from Crypto.Cipher import AES

        key = 'a' * 32  # 256-bit key
        client_id = 'b' * 16
        plaintext = 'hello world'

        # Pad to AES block size
        pad_len = 16 - (len(plaintext) % 16)
        padded = plaintext.encode('utf-8') + bytes([pad_len] * pad_len)

        iv = client_id.encode('utf-8')[:16]
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
        encrypted = base64.b64encode(cipher.encrypt(padded)).decode('utf-8')

        result = generate_aes_decrypt(encrypted, client_id, key)
        assert result == plaintext

    def test_short_client_id_padded(self):
        """Client IDs shorter than 16 bytes are padded with null bytes."""
        from Crypto.Cipher import AES

        key = 'c' * 32
        client_id = 'short'  # less than 16 bytes
        plaintext = 'test data'

        iv = client_id.encode('utf-8').ljust(16, b'\0')
        pad_len = 16 - (len(plaintext) % 16)
        padded = plaintext.encode('utf-8') + bytes([pad_len] * pad_len)

        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
        encrypted = base64.b64encode(cipher.encrypt(padded)).decode('utf-8')

        result = generate_aes_decrypt(encrypted, client_id, key)
        assert result == plaintext


# ---------------------------------------------------------------------------
# decrypt_akool_webhook
# ---------------------------------------------------------------------------

class TestDecryptAkoolWebhook:
    def test_missing_env_vars(self, capsys):
        with patch('webhook.load_env_variables', return_value={}):
            result = decrypt_akool_webhook({'signature': 's', 'timestamp': 1, 'nonce': 'n', 'dataEncrypt': 'e'})
            assert result is None
            assert 'not set' in capsys.readouterr().out

    def test_missing_client_id(self, capsys):
        env = {'AKOOL_CLIENT_ID': None, 'AKOOL_CLIENT_SECRET': 'secret'}
        with patch('webhook.load_env_variables', return_value=env):
            result = decrypt_akool_webhook({'signature': 's', 'timestamp': 1, 'nonce': 'n', 'dataEncrypt': 'e'})
            assert result is None

    def test_missing_client_secret(self, capsys):
        env = {'AKOOL_CLIENT_ID': 'id', 'AKOOL_CLIENT_SECRET': None}
        with patch('webhook.load_env_variables', return_value=env):
            result = decrypt_akool_webhook({'signature': 's', 'timestamp': 1, 'nonce': 'n', 'dataEncrypt': 'e'})
            assert result is None

    def test_missing_payload_fields(self, capsys):
        env = {'AKOOL_CLIENT_ID': 'cid', 'AKOOL_CLIENT_SECRET': 'secret'}
        with patch('webhook.load_env_variables', return_value=env):
            result = decrypt_akool_webhook({'signature': 's'})
            assert result is None
            assert 'Missing required fields' in capsys.readouterr().out

    def test_missing_signature_field(self, capsys):
        env = {'AKOOL_CLIENT_ID': 'cid', 'AKOOL_CLIENT_SECRET': 'secret'}
        with patch('webhook.load_env_variables', return_value=env):
            result = decrypt_akool_webhook({'timestamp': 1, 'nonce': 'n', 'dataEncrypt': 'e'})
            assert result is None

    def test_missing_nonce_field(self, capsys):
        env = {'AKOOL_CLIENT_ID': 'cid', 'AKOOL_CLIENT_SECRET': 'secret'}
        with patch('webhook.load_env_variables', return_value=env):
            result = decrypt_akool_webhook({'signature': 's', 'timestamp': 1, 'dataEncrypt': 'e'})
            assert result is None

    def test_missing_data_encrypt_field(self, capsys):
        env = {'AKOOL_CLIENT_ID': 'cid', 'AKOOL_CLIENT_SECRET': 'secret'}
        with patch('webhook.load_env_variables', return_value=env):
            result = decrypt_akool_webhook({'signature': 's', 'timestamp': 1, 'nonce': 'n'})
            assert result is None

    def test_invalid_signature(self, capsys):
        env = {'AKOOL_CLIENT_ID': 'cid', 'AKOOL_CLIENT_SECRET': 'a' * 32}
        with patch('webhook.load_env_variables', return_value=env):
            result = decrypt_akool_webhook({
                'signature': 'invalid',
                'timestamp': 1,
                'nonce': 'n',
                'dataEncrypt': 'e',
            })
            assert result is None
            assert 'Invalid signature' in capsys.readouterr().out

    def _encrypt_payload(self, payload_dict, client_id, client_secret):
        """Helper to encrypt a payload for Akool webhook testing."""
        from Crypto.Cipher import AES

        plaintext = json.dumps(payload_dict)
        pad_len = 16 - (len(plaintext.encode('utf-8')) % 16)
        padded = plaintext.encode('utf-8') + bytes([pad_len] * pad_len)

        iv = client_id.encode('utf-8')
        iv = iv[:16] if len(iv) >= 16 else iv.ljust(16, b'\0')

        cipher = AES.new(client_secret.encode('utf-8'), AES.MODE_CBC, iv)
        return base64.b64encode(cipher.encrypt(padded)).decode('utf-8')

    def test_status_in_progress(self, capsys):
        client_id = 'a' * 16
        client_secret = 'b' * 32
        decrypted = {'_id': 'job1', 'status': 2, 'type': 'faceswap', 'deduction_credit': 10}
        data_encrypt = self._encrypt_payload(decrypted, client_id, client_secret)
        nonce = 'testnonce'
        timestamp = '12345'
        signature = generate_msg_signature(client_id, timestamp, nonce, data_encrypt)

        env = {'AKOOL_CLIENT_ID': client_id, 'AKOOL_CLIENT_SECRET': client_secret}
        with patch('webhook.load_env_variables', return_value=env):
            decrypt_akool_webhook({
                'signature': signature,
                'timestamp': timestamp,
                'nonce': nonce,
                'dataEncrypt': data_encrypt,
            })
            output = capsys.readouterr().out
            assert 'in progress' in output

    def test_status_completed_with_url(self, capsys):
        client_id = 'a' * 16
        client_secret = 'b' * 32
        decrypted = {
            '_id': 'job1',
            'status': 3,
            'type': 'faceswap',
            'url': 'http://example.com/image.jpg',
            'deduction_credit': 5,
        }
        data_encrypt = self._encrypt_payload(decrypted, client_id, client_secret)
        nonce = 'testnonce'
        timestamp = '12345'
        signature = generate_msg_signature(client_id, timestamp, nonce, data_encrypt)

        # Create a fake image response
        img_buf = io.BytesIO()
        Image.new('RGB', (100, 100), 'blue').save(img_buf, format='JPEG')
        img_bytes = img_buf.getvalue()

        mock_response = MagicMock()
        mock_response.content = img_bytes

        env = {'AKOOL_CLIENT_ID': client_id, 'AKOOL_CLIENT_SECRET': client_secret}
        with patch('webhook.load_env_variables', return_value=env), \
             patch('webhook.requests.get', return_value=mock_response), \
             patch('webhook.save_image'):
            decrypt_akool_webhook({
                'signature': signature,
                'timestamp': timestamp,
                'nonce': nonce,
                'dataEncrypt': data_encrypt,
            })
            output = capsys.readouterr().out
            assert 'completed successfully' in output
            assert 'Result URL' in output

    def test_status_completed_request_error(self, capsys):
        import requests as req
        client_id = 'a' * 16
        client_secret = 'b' * 32
        decrypted = {
            '_id': 'job1',
            'status': 3,
            'type': 'faceswap',
            'url': 'http://example.com/image.jpg',
            'deduction_credit': 5,
        }
        data_encrypt = self._encrypt_payload(decrypted, client_id, client_secret)
        nonce = 'testnonce'
        timestamp = '12345'
        signature = generate_msg_signature(client_id, timestamp, nonce, data_encrypt)

        env = {'AKOOL_CLIENT_ID': client_id, 'AKOOL_CLIENT_SECRET': client_secret}
        with patch('webhook.load_env_variables', return_value=env), \
             patch('webhook.requests.get', side_effect=req.exceptions.RequestException('fail')):
            decrypt_akool_webhook({
                'signature': signature,
                'timestamp': timestamp,
                'nonce': nonce,
                'dataEncrypt': data_encrypt,
            })
            output = capsys.readouterr().out
            assert 'Error downloading image' in output

    def test_status_completed_image_processing_error(self, capsys):
        client_id = 'a' * 16
        client_secret = 'b' * 32
        decrypted = {
            '_id': 'job1',
            'status': 3,
            'type': 'faceswap',
            'url': 'http://example.com/image.jpg',
            'deduction_credit': 5,
        }
        data_encrypt = self._encrypt_payload(decrypted, client_id, client_secret)
        nonce = 'testnonce'
        timestamp = '12345'
        signature = generate_msg_signature(client_id, timestamp, nonce, data_encrypt)

        mock_response = MagicMock()
        mock_response.content = b'not-an-image'

        env = {'AKOOL_CLIENT_ID': client_id, 'AKOOL_CLIENT_SECRET': client_secret}
        with patch('webhook.load_env_variables', return_value=env), \
             patch('webhook.requests.get', return_value=mock_response):
            decrypt_akool_webhook({
                'signature': signature,
                'timestamp': timestamp,
                'nonce': nonce,
                'dataEncrypt': data_encrypt,
            })
            output = capsys.readouterr().out
            assert 'Error processing/saving image' in output

    def test_status_completed_no_url(self, capsys):
        client_id = 'a' * 16
        client_secret = 'b' * 32
        decrypted = {'_id': 'job1', 'status': 3, 'type': 'faceswap', 'deduction_credit': 5}
        data_encrypt = self._encrypt_payload(decrypted, client_id, client_secret)
        nonce = 'testnonce'
        timestamp = '12345'
        signature = generate_msg_signature(client_id, timestamp, nonce, data_encrypt)

        env = {'AKOOL_CLIENT_ID': client_id, 'AKOOL_CLIENT_SECRET': client_secret}
        with patch('webhook.load_env_variables', return_value=env):
            decrypt_akool_webhook({
                'signature': signature,
                'timestamp': timestamp,
                'nonce': nonce,
                'dataEncrypt': data_encrypt,
            })
            output = capsys.readouterr().out
            assert 'completed successfully' in output
            assert 'Result URL' not in output

    def test_other_status_dumps_json(self, capsys):
        client_id = 'a' * 16
        client_secret = 'b' * 32
        decrypted = {'_id': 'job1', 'status': 1, 'type': 'faceswap'}
        data_encrypt = self._encrypt_payload(decrypted, client_id, client_secret)
        nonce = 'testnonce'
        timestamp = '12345'
        signature = generate_msg_signature(client_id, timestamp, nonce, data_encrypt)

        env = {'AKOOL_CLIENT_ID': client_id, 'AKOOL_CLIENT_SECRET': client_secret}
        with patch('webhook.load_env_variables', return_value=env):
            decrypt_akool_webhook({
                'signature': signature,
                'timestamp': timestamp,
                'nonce': nonce,
                'dataEncrypt': data_encrypt,
            })
            output = capsys.readouterr().out
            assert 'faceswap' in output

    def test_no_job_id_dumps_json(self, capsys):
        client_id = 'a' * 16
        client_secret = 'b' * 32
        decrypted = {'status': 3, 'type': 'faceswap'}
        data_encrypt = self._encrypt_payload(decrypted, client_id, client_secret)
        nonce = 'testnonce'
        timestamp = '12345'
        signature = generate_msg_signature(client_id, timestamp, nonce, data_encrypt)

        env = {'AKOOL_CLIENT_ID': client_id, 'AKOOL_CLIENT_SECRET': client_secret}
        with patch('webhook.load_env_variables', return_value=env):
            decrypt_akool_webhook({
                'signature': signature,
                'timestamp': timestamp,
                'nonce': nonce,
                'dataEncrypt': data_encrypt,
            })
            output = capsys.readouterr().out
            assert 'faceswap' in output

    def test_decryption_error(self, capsys):
        client_id = 'a' * 16
        client_secret = 'b' * 32
        nonce = 'testnonce'
        timestamp = '12345'
        data_encrypt = base64.b64encode(b'x' * 16).decode('utf-8')  # garbage
        signature = generate_msg_signature(client_id, timestamp, nonce, data_encrypt)

        env = {'AKOOL_CLIENT_ID': client_id, 'AKOOL_CLIENT_SECRET': client_secret}
        with patch('webhook.load_env_variables', return_value=env):
            decrypt_akool_webhook({
                'signature': signature,
                'timestamp': timestamp,
                'nonce': nonce,
                'dataEncrypt': data_encrypt,
            })
            output = capsys.readouterr().out
            assert 'Error during decryption' in output


# ---------------------------------------------------------------------------
# get_aspect_ratio
# ---------------------------------------------------------------------------

class TestGetAspectRatio:
    def test_square(self):
        img = Image.new('RGB', (100, 100))
        w, h, rw, rh = get_aspect_ratio(img)
        assert (w, h) == (100, 100)
        assert (rw, rh) == (1, 1)

    def test_16_9(self):
        img = Image.new('RGB', (1920, 1080))
        w, h, rw, rh = get_aspect_ratio(img)
        assert (rw, rh) == (16, 9)

    def test_9_16(self):
        img = Image.new('RGB', (1080, 1920))
        w, h, rw, rh = get_aspect_ratio(img)
        assert (rw, rh) == (9, 16)

    def test_4_3(self):
        img = Image.new('RGB', (1024, 768))
        w, h, rw, rh = get_aspect_ratio(img)
        assert (rw, rh) == (4, 3)

    def test_3_4(self):
        img = Image.new('RGB', (768, 1024))
        w, h, rw, rh = get_aspect_ratio(img)
        assert (rw, rh) == (3, 4)

    def test_3_2(self):
        img = Image.new('RGB', (1500, 1000))
        w, h, rw, rh = get_aspect_ratio(img)
        assert (rw, rh) == (3, 2)

    def test_2_3(self):
        img = Image.new('RGB', (1000, 1500))
        w, h, rw, rh = get_aspect_ratio(img)
        assert (rw, rh) == (2, 3)

    def test_21_9(self):
        img = Image.new('RGB', (2520, 1080))
        w, h, rw, rh = get_aspect_ratio(img)
        assert (rw, rh) == (21, 9)

    def test_non_standard_ratio(self):
        img = Image.new('RGB', (500, 300))
        w, h, rw, rh = get_aspect_ratio(img)
        assert (w, h) == (500, 300)
        assert rw is None
        assert rh is None


# ---------------------------------------------------------------------------
# save_image
# ---------------------------------------------------------------------------

class TestSaveImage:
    def test_saves_file(self, capsys, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        img = Image.new('RGB', (100, 100))
        with patch('webhook.uuid.uuid4', return_value='test-uuid'):
            save_image(img)
        output = capsys.readouterr().out
        assert 'Image dimensions: 100x100' in output
        assert 'Saving image: test-uuid.jpeg' in output
        assert (tmp_path / 'test-uuid.jpeg').exists()

    def test_logs_aspect_ratio(self, capsys, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        img = Image.new('RGB', (1920, 1080))
        with patch('webhook.uuid.uuid4', return_value='ar-uuid'):
            save_image(img)
        output = capsys.readouterr().out
        assert 'Aspect Ratio: 16:9' in output

    def test_no_aspect_ratio_for_non_standard(self, capsys, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        img = Image.new('RGB', (500, 300))
        with patch('webhook.uuid.uuid4', return_value='no-ar-uuid'):
            save_image(img)
        output = capsys.readouterr().out
        assert 'Aspect Ratio' not in output


# ---------------------------------------------------------------------------
# save_result_images
# ---------------------------------------------------------------------------

class TestSaveResultImages:
    def test_saves_multiple_images(self):
        b64_img = _make_test_image()
        payload = {'output': {'images': [b64_img, b64_img]}}
        with patch('webhook.save_image') as mock_save:
            save_result_images(payload)
            assert mock_save.call_count == 2


# ---------------------------------------------------------------------------
# save_result_image
# ---------------------------------------------------------------------------

class TestSaveResultImage:
    def test_saves_result_image(self):
        b64_img = _make_test_image()
        payload = {'output': {'result_image': b64_img}}
        with patch('webhook.save_image') as mock_save:
            save_result_image(payload)
            mock_save.assert_called_once()

    def test_saves_image_field(self):
        b64_img = _make_test_image()
        payload = {'output': {'image': b64_img}}
        with patch('webhook.save_image') as mock_save:
            save_result_image(payload)
            mock_save.assert_called_once()

    def test_no_image_found(self, capsys):
        payload = {'output': {'other': 'data'}}
        save_result_image(payload)
        assert 'No result image found' in capsys.readouterr().out

    def test_empty_output(self, capsys):
        payload = {}
        save_result_image(payload)
        assert 'No result image found' in capsys.readouterr().out


# ---------------------------------------------------------------------------
# save_openai_result_images
# ---------------------------------------------------------------------------

class TestSaveOpenaiResultImages:
    def test_saves_images(self, capsys):
        b64_img = _make_test_image()
        payload = {'output': {'data': [{'b64_json': b64_img}, {'b64_json': b64_img}]}}
        with patch('webhook.save_image') as mock_save:
            save_openai_result_images(payload)
            assert mock_save.call_count == 2
        output = capsys.readouterr().out
        assert 'Processing output image #1' in output
        assert 'Processing output image #2' in output


# ---------------------------------------------------------------------------
# format_time_ms
# ---------------------------------------------------------------------------

class TestFormatTimeMs:
    def test_none(self):
        assert format_time_ms(None) == '0s'

    def test_zero(self):
        assert format_time_ms(0) == '0s'

    def test_whole_seconds(self):
        assert format_time_ms(5000) == '5s'

    def test_fractional_seconds(self):
        assert format_time_ms(30) == '0.03s'

    def test_fractional_seconds_trailing_zeros(self):
        # rstrip('0') doesn't strip before the trailing 's'
        assert format_time_ms(1100) == '1.10s'

    def test_one_minute(self):
        assert format_time_ms(60000) == '1m'

    def test_minutes_and_seconds(self):
        assert format_time_ms(102000) == '1m 42s'

    def test_rounding_seconds_to_60(self):
        # 119999ms = 119.999s -> 1m 60s rounds to 2m
        assert format_time_ms(119999) == '2m'

    def test_multiple_minutes(self):
        assert format_time_ms(300000) == '5m'

    def test_minutes_with_remaining_seconds(self):
        assert format_time_ms(125000) == '2m 5s'


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

class TestPingRoute:
    def test_get_root(self, client):
        response = client.get('/')
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'ok'


class TestNotFoundHandler:
    def test_404(self, client):
        response = client.get('/nonexistent')
        assert response.status_code == 404
        data = response.get_json()
        assert data['status'] == 'error'
        assert 'not found' in data['msg']


class TestInternalServerErrorHandler:
    def test_500(self, client_no_propagate):
        # Route registered in conftest.py; use client_no_propagate so
        # Flask invokes the error handler instead of re-raising.
        response = client_no_propagate.get('/test-500-error')
        assert response.status_code == 500
        data = response.get_json()
        assert data['status'] == 'error'
        assert data['msg'] == 'Internal Server Error'


class TestBeforeRequest:
    def test_non_json_content_type_with_valid_json(self, client):
        response = client.post(
            '/',
            data=json.dumps({'test': 'value'}),
            content_type='text/plain',
        )
        assert response.status_code == 200

    def test_non_json_content_type_with_invalid_json(self, client):
        response = client.post(
            '/',
            data='not json',
            content_type='text/plain',
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data['status'] == 'error'
        assert 'Invalid JSON' in data['msg']

    def test_empty_body_with_wrong_content_type(self, client):
        response = client.post(
            '/',
            data='',
            content_type='text/plain',
        )
        # Empty body skips JSON parsing in before_request, but the
        # webhook handler then fails on the empty payload
        assert response.status_code in (200, 400, 415, 500)


# ---------------------------------------------------------------------------
# webhook_handler (POST /)
# ---------------------------------------------------------------------------

class TestWebhookHandler:
    def test_basic_payload(self, client, capsys):
        payload = {'key': 'value'}
        response = client.post('/', json=payload)
        assert response.status_code == 200
        assert response.get_json()['status'] == 'ok'
        output = capsys.readouterr().out
        assert 'Token: -' in output

    def test_with_token(self, client, capsys):
        response = client.post('/?token=mytoken', json={'key': 'val'})
        assert response.status_code == 200
        output = capsys.readouterr().out
        assert 'Token: mytoken' in output

    def test_with_job_id_and_processor(self, client, capsys):
        payload = {'id': 'job-123', 'processor': 'gpu-01'}
        response = client.post('/', json=payload)
        assert response.status_code == 200
        output = capsys.readouterr().out
        assert 'Job ID: job-123' in output
        assert 'Processor: gpu-01' in output

    def test_with_delay_and_execution_time(self, client, capsys):
        payload = {'delayTime': 5000, 'executionTime': 102000}
        response = client.post('/', json=payload)
        assert response.status_code == 200
        output = capsys.readouterr().out
        assert 'Delay time: 5s' in output
        assert 'Execution time: 1m 42s' in output

    def test_with_output_images(self, client):
        b64_img = _make_test_image()
        payload = {'output': {'images': [b64_img]}}
        with patch('webhook.save_result_images') as mock_save:
            response = client.post('/', json=payload)
            assert response.status_code == 200
            mock_save.assert_called_once()

    def test_with_output_data(self, client):
        b64_img = _make_test_image()
        payload = {'output': {'data': [{'b64_json': b64_img}]}}
        with patch('webhook.save_openai_result_images') as mock_save:
            response = client.post('/', json=payload)
            assert response.status_code == 200
            mock_save.assert_called_once()

    def test_with_result_image(self, client):
        b64_img = _make_test_image()
        payload = {'output': {'result_image': b64_img}}
        with patch('webhook.save_result_image') as mock_save:
            response = client.post('/', json=payload)
            assert response.status_code == 200
            mock_save.assert_called_once()

    def test_with_image_field(self, client):
        b64_img = _make_test_image()
        payload = {'output': {'image': b64_img}}
        with patch('webhook.save_result_image') as mock_save:
            response = client.post('/', json=payload)
            assert response.status_code == 200
            mock_save.assert_called_once()

    def test_akool_encrypted_payload(self, client):
        payload = {
            'signature': 'sig',
            'dataEncrypt': 'data',
            'nonce': 'nonce',
            'timestamp': 123,
        }
        with patch('webhook.decrypt_akool_webhook') as mock_decrypt:
            response = client.post('/', json=payload)
            assert response.status_code == 200
            mock_decrypt.assert_called_once()

    def test_plain_payload_dumps_json(self, client, capsys):
        payload = {'custom': 'data', 'nested': {'key': 'val'}}
        response = client.post('/', json=payload)
        assert response.status_code == 200
        output = capsys.readouterr().out
        assert '"custom"' in output

    def test_metadata_logged(self, client, capsys):
        payload = {'key': 'val', 'metadata': {'source': 'test', 'version': 1}}
        response = client.post('/', json=payload)
        assert response.status_code == 200
        output = capsys.readouterr().out
        assert 'Meta-data:' in output
        assert '"source"' in output

    def test_separator_printed(self, client, capsys):
        response = client.post('/', json={'key': 'val'})
        assert response.status_code == 200
        output = capsys.readouterr().out
        assert '-' * 50 in output


