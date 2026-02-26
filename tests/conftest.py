import pytest
from webhook import app


# Register a test-only route before any requests are handled,
# so it can be used to exercise the 500 error handler.
@app.route('/test-500-error')
def _test_500_route():
    raise RuntimeError('test error')


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def client_no_propagate():
    """Client that doesn't propagate exceptions, so 500 error handlers run."""
    app.config['TESTING'] = True
    app.config['PROPAGATE_EXCEPTIONS'] = False
    with app.test_client() as client:
        yield client
    app.config['PROPAGATE_EXCEPTIONS'] = None
