#!/usr/bin/env python3
import requests
import json


def test_post_request():
    """Test POST request to local server."""
    url = 'http://127.0.0.1:8090/'

    payload = {
        'test_key': 'test_value',
        'number': 123
    }

    try:
        response = requests.post(
            url,
            data=json.dumps(payload),
            headers={
                'User-Agent': 'Test Webhook Logger',
                'Content-Length': '16',
                'Accept-Encoding': 'gzip'
            }
        )

        print(f'Status Code: {response.status_code}')
        print('\nResponse Headers:')
        for key, value in response.headers.items():
            print(f'{key}: {value}')

        print('\nResponse Body:')
        try:
            print(json.dumps(response.json(), indent=2))
        except:
            print(response.text)

    except requests.exceptions.ConnectionError:
        print(f'Failed to connect to {url}')
    except Exception as e:
        print(f'Error: {str(e)}')


if __name__ == '__main__':
    test_post_request()
