# Changelog

All notable changes to this project will be documented in this file.

## [2.0.0] - 2026-02-26

### Added

- Unit test suite with 100% code coverage.
- `pyproject.toml` with pytest and coverage configuration.
- GitHub Actions workflow to run tests on Python 3.10, 3.11, 3.12, 3.13 and 3.14.

### Changed

- Refactored to remove code duplication.
- Improved handling of output.
- Log metadata if it exists.

## [1.0.0] - 2025-10-07

### Added

- Flask-based webhook listener with configurable host and port.
- Health check endpoint (`GET /`).
- Webhook handler (`POST /`) with token query parameter support.
- Automatic Content-Type injection for requests missing `application/json`.
- Save output images from base64-encoded webhook payloads.
- Support for OpenAI and Google Gemini webhook image formats.
- Support for Akool Face Swap API webhooks with AES-CBC decryption and
  SHA-1 signature verification.
- Log image dimensions and aspect ratio of output images.
- Display job ID and processor if present in the webhook payload.
- Calculate and display delay time and execution time (RunPod specific).
- Separator line between webhook entries for readability.
- Custom error handlers for 404 and 500 responses.
