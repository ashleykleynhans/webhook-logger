# Webhook logger for debugging/testing Webhooks

## Prerequisites

* Install [ngrok](https://ngrok.com/download).

## Installation

### Clone the repo

```bash
git clone https://github.com/ashleykleynhans/webhook-logger.git
cd webhook-logger
```

### Create venv and install requirements

#### Linux and Mac

```
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

#### Windows

```
python3 -m venv venv
venv\Scripts\activate
pip3 install -r requirements.txt
```

## Running

In the same terminal that you activated the venv:

```bash
python3 webhook.py -p 8100
```

In a new terminal:

```bash
ngrok http 8100
```

Use the `Forwarding` URL from ngrok (eg. https://f8e2-45-222-5-113.ngrok.io)
as your Webhook URL.
