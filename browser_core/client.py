from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlparse

from .contracts import ContractError
from .control_files import decode_strict_json_bytes
from .http_deadline import clamp_urllib_response_read_timeout
from .numeric import is_finite_number


LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
# A valid job-list response can exceed 2 MiB before its 100-row limit.
# Match the control service's bounded JSON response envelope.
MAX_JSON_RESPONSE = 8 * 1024 * 1024
MAX_ARTIFACT_RESPONSE = 64 * 1024 * 1024
MAX_JSON_REQUEST = 1024 * 1024
MAX_ARTIFACT_REQUEST = 64 * 1024 * 1024
MAX_REQUEST_PATH_BYTES = 4096
MAX_RESPONSE_READ_CALLS = 65_536
MAX_CONTROL_REVISION = (1 << 63) - 2
RESOURCE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _open_control_request(request: urllib.request.Request, *, timeout: float):
    parsed = urlparse(request.full_url)
    if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "::1"}:
        raise ContractError("plain HTTP control requests require literal loopback")
    handlers: list[Any] = [_NoRedirectHandler()]
    if parsed.hostname in LOOPBACK_HOSTS:
        handlers.append(urllib.request.ProxyHandler({}))
    opener = urllib.request.build_opener(*handlers)
    return opener.open(request, timeout=timeout)


def _optional_revision(value: Any) -> int | None:
    if value is None:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= MAX_CONTROL_REVISION
    ):
        raise ContractError("control client expected revision is invalid")
    return value


def _lease_duration(value: Any, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 5 <= value <= 3600:
        raise ContractError(f"control client {label} is invalid")
    return value


def _lease_token(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 1024
        or any(not 0x21 <= ord(character) <= 0x7E for character in value)
    ):
        raise ContractError("control client lease token is invalid")
    return value


def _normalize_response_error(error: BaseException) -> BaseException:
    if isinstance(error, ContractError):
        return error
    if isinstance(
        error, (AttributeError, OSError, RuntimeError, TypeError, ValueError)
    ):
        return ContractError(
            f"control service response failed ({type(error).__name__})"
        )
    return error


def _read_control_response_payload(
    response: Any,
    *,
    maximum: int,
    deadline_monotonic: float | None = None,
    expected_content_type: str | None = None,
) -> bytes:
    if (
        type(maximum) is not int
        or not 1 <= maximum <= MAX_ARTIFACT_RESPONSE
    ):
        raise ContractError("control client response limit is invalid")
    if deadline_monotonic is not None and not is_finite_number(deadline_monotonic):
        raise ContractError("control client response deadline is invalid")
    payload: bytes | None = None
    primary_error: BaseException | None = None
    try:
        status = response.getcode()
        if type(status) is not int or status not in {200, 201}:
            raise ContractError("control service response status is invalid")
        try:
            lengths = response.headers.get_all("Content-Length", [])
        except (AttributeError, TypeError, ValueError):
            raise ContractError(
                "control service response content length is invalid"
            ) from None
        if (
            not isinstance(lengths, list)
            or len(lengths) > 1
            or (
                lengths
                and (
                    not isinstance(lengths[0], str)
                    or len(lengths[0]) > 20
                    or re.fullmatch(r"0|[1-9][0-9]*", lengths[0]) is None
                )
            )
        ):
            raise ContractError("control service response content length is invalid")
        if lengths and int(lengths[0]) > maximum:
            raise ContractError("control service response exceeds the client limit")
        if expected_content_type is not None:
            try:
                content_types = response.headers.get_all("Content-Type", [])
            except (AttributeError, TypeError, ValueError):
                raise ContractError(
                    "control service response content type is invalid"
                ) from None
            if (
                not isinstance(content_types, list)
                or len(content_types) != 1
                or not isinstance(content_types[0], str)
                or content_types[0].lower() != expected_content_type
            ):
                raise ContractError("control service response content type is invalid")
        try:
            transfer_encodings = response.headers.get_all("Transfer-Encoding", [])
        except (AttributeError, TypeError, ValueError):
            raise ContractError(
                "control service response transfer encoding is invalid"
            ) from None
        if not isinstance(transfer_encodings, list) or transfer_encodings:
            raise ContractError("control service response transfer encoding is unsupported")
        try:
            content_encodings = response.headers.get_all("Content-Encoding", [])
        except (AttributeError, TypeError, ValueError):
            raise ContractError(
                "control service response content encoding is invalid"
            ) from None
        if not isinstance(content_encodings, list) or content_encodings:
            raise ContractError("control service response content encoding is unsupported")
        body = bytearray()
        reader = getattr(response, "read1", None)
        if not callable(reader):
            reader = response.read
        for _ in range(MAX_RESPONSE_READ_CALLS):
            if deadline_monotonic is not None and not clamp_urllib_response_read_timeout(
                response, deadline_monotonic - time.monotonic()
            ):
                raise ContractError("control service response deadline exceeded")
            requested = maximum + 1 - len(body)
            try:
                chunk = reader(requested)
            except TimeoutError:
                if deadline_monotonic is not None:
                    raise ContractError(
                        "control service response deadline exceeded"
                    ) from None
                raise
            if deadline_monotonic is not None and time.monotonic() > deadline_monotonic:
                raise ContractError("control service response deadline exceeded")
            if type(chunk) is not bytes or len(chunk) > requested:
                raise ContractError("control service response body is invalid")
            if not chunk:
                break
            if len(chunk) > maximum - len(body):
                raise ContractError("control service response exceeds the client limit")
            body.extend(chunk)
        else:
            raise ContractError("control service response has too many fragments")
        payload = bytes(body)
        if lengths and len(payload) != int(lengths[0]):
            raise ContractError("control service response body is incomplete")
    except BaseException as exc:
        primary_error = _normalize_response_error(exc)

    cleanup_error: ContractError | None = None
    try:
        response.close()
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        cleanup_error = ContractError(
            "control service response cleanup failed (response-close)"
        )
    if cleanup_error is not None:
        if primary_error is not None:
            raise cleanup_error from primary_error
        raise cleanup_error from None
    if primary_error is not None:
        raise primary_error from None
    if payload is None:
        raise ContractError("control service response body is invalid")
    if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
        raise ContractError("control service response deadline exceeded")
    return payload


def _read_rejection_diagnostic(
    response: urllib.error.HTTPError, *, deadline_monotonic: float | None = None
) -> str:
    error_body = bytearray()
    complete = False
    try:
        reader = getattr(response, "read1", None)
        if not callable(reader):
            reader = response.read
        for _ in range(MAX_RESPONSE_READ_CALLS):
            if deadline_monotonic is not None and not clamp_urllib_response_read_timeout(
                response, deadline_monotonic - time.monotonic()
            ):
                break
            requested = MAX_JSON_RESPONSE + 1 - len(error_body)
            candidate = reader(requested)
            if type(candidate) is not bytes or (
                deadline_monotonic is not None
                and time.monotonic() > deadline_monotonic
            ) or len(candidate) > requested:
                break
            if not candidate:
                complete = True
                break
            if len(candidate) > MAX_JSON_RESPONSE - len(error_body):
                break
            error_body.extend(candidate)
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        pass
    try:
        response.close()
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        raise ContractError(
            "control service response cleanup failed (response-close)"
        ) from None
    return hashlib.sha256(error_body if complete else b"").hexdigest()[:16]


@dataclass(frozen=True, repr=False)
class ControlClient:
    base_url: str
    bearer_token: str | None = None
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        if (
            not isinstance(self.base_url, str)
            or not 1 <= len(self.base_url) <= 2048
            or any(not 0x21 <= ord(character) <= 0x7E for character in self.base_url)
        ):
            raise ContractError("control client URL is invalid")
        try:
            parsed = urlparse(self.base_url)
            parsed_port = parsed.port
            parsed_hostname = parsed.hostname
        except ValueError:
            raise ContractError("control client URL is invalid") from None
        if (
            parsed.scheme not in {"http", "https"}
            or parsed_hostname is None
            or parsed_port is None
            or not 1 <= parsed_port <= 65535
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or "?" in self.base_url
            or "#" in self.base_url
            or parsed.path not in {"", "/"}
        ):
            raise ContractError(
                "control client URL must be an origin with an explicit port"
            )
        if "\\" in parsed.netloc or "%" in parsed.netloc:
            raise ContractError("control client URL host is ambiguous")
        try:
            ipaddress.ip_address(parsed_hostname)
        except ValueError:
            final_label = parsed_hostname.rstrip(".").rsplit(".", 1)[-1]
            if final_label.isdecimal() or re.fullmatch(
                r"0[xX][0-9A-Fa-f]+", final_label
            ):
                raise ContractError("control client URL host is ambiguous") from None
        if parsed.scheme == "http" and parsed_hostname not in LOOPBACK_HOSTS:
            raise ContractError("remote control clients require HTTPS")
        if self.bearer_token is not None and (
            not isinstance(self.bearer_token, str)
            or not self.bearer_token
            or len(self.bearer_token) > 1024
            or any(
                character.isspace() or ord(character) < 0x21 or ord(character) > 0x7E
                for character in self.bearer_token
            )
        ):
            raise ContractError("control client bearer token is invalid")
        if not is_finite_number(self.timeout_seconds) or not (
            0 < self.timeout_seconds <= 300
        ):
            raise ContractError("control client timeout must be finite in (0, 300]")
        # Plain HTTP is permitted only for loopback. Resolve the localhost
        # alias ourselves so a hosts-file override cannot receive the token.
        base_url = (
            f"http://127.0.0.1:{parsed_port}"
            if parsed.scheme == "http" and parsed_hostname == "localhost"
            else self.base_url.rstrip("/")
        )
        object.__setattr__(self, "base_url", base_url)

    def __repr__(self) -> str:
        return f"ControlClient(base_url={self.base_url!r}, bearer_token=<redacted>, timeout_seconds={self.timeout_seconds!r})"

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        raw_body: bytes | None = None,
        headers: dict[str, str] | None = None,
        maximum: int = MAX_JSON_RESPONSE,
        expect_json: bool = True,
        authenticated: bool = True,
        allow_null: bool = False,
    ) -> Any:
        if not isinstance(method, str) or method not in {"GET", "POST", "PUT"}:
            raise ContractError("control client method is invalid")
        if not isinstance(path, str) or not path.startswith("/"):
            raise ContractError("control client path is invalid")
        try:
            path_bytes = path.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            raise ContractError("control client path is invalid") from None
        if (
            len(path_bytes) > MAX_REQUEST_PATH_BYTES
            or "?" in path
            or "#" in path
            or any(
                ord(character) < 0x20 or ord(character) == 0x7F for character in path
            )
        ):
            raise ContractError("control client path is invalid")
        for flag, label in (
            (expect_json, "response JSON policy"),
            (authenticated, "authentication policy"),
            (allow_null, "null response policy"),
        ):
            if not isinstance(flag, bool):
                raise ContractError(f"control client {label} is invalid")
        if (
            isinstance(maximum, bool)
            or not isinstance(maximum, int)
            or not 1 <= maximum <= MAX_ARTIFACT_RESPONSE
        ):
            raise ContractError("control client response limit is invalid")
        if json_body is not None and raw_body is not None:
            raise ContractError("control client request body is ambiguous")
        if json_body is not None and not isinstance(json_body, dict):
            raise ContractError("control client JSON request must be an object")
        if raw_body is not None and not isinstance(raw_body, bytes):
            raise ContractError("control client raw request must be bytes")
        if headers is not None and (
            not isinstance(headers, dict)
            or len(headers) > 32
            or any(
                not isinstance(name, str)
                or HEADER_NAME_RE.fullmatch(name) is None
                or name not in {
                    "Content-Type",
                    "X-Artifact-Media-Type",
                    "X-Artifact-Visibility",
                }
                or not isinstance(value, str)
                or len(value) > 1024
                or any(not 0x20 <= ord(character) <= 0x7E for character in value)
                for name, value in headers.items()
            )
        ):
            raise ContractError("control client headers are invalid")
        request_headers = {"Accept": "application/json"}
        if headers:
            request_headers.update(headers)
        body = raw_body
        if json_body is not None:
            try:
                body = json.dumps(
                    json_body,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                    allow_nan=False,
                ).encode("ascii")
            except (OverflowError, RecursionError, TypeError, ValueError):
                raise ContractError(
                    "control client JSON request is not strict JSON"
                ) from None
            if len(body) > MAX_JSON_REQUEST:
                raise ContractError("control client JSON request exceeds limit")
            try:
                decode_strict_json_bytes(body, label="control client JSON request")
            except ContractError:
                raise ContractError("control client JSON request is not strict JSON") from None
            request_headers["Content-Type"] = "application/json"
        if raw_body is not None and len(raw_body) > MAX_ARTIFACT_REQUEST:
            raise ContractError("control client raw request exceeds limit")
        if method == "GET" and body is not None:
            raise ContractError("control client GET request cannot carry a body")
        if authenticated:
            if self.bearer_token is None:
                raise ContractError("control client bearer token is required")
            request_headers["Authorization"] = f"Bearer {self.bearer_token}"
        try:
            request = urllib.request.Request(
                self.base_url + path,
                data=body,
                headers=request_headers,
                method=method,
            )
        except (OSError, TypeError, ValueError) as exc:
            raise ContractError(
                f"control client request could not be built ({type(exc).__name__})"
            ) from None
        try:
            deadline = time.monotonic() + self.timeout_seconds
            response = _open_control_request(request, timeout=self.timeout_seconds)
            payload = _read_control_response_payload(
                response,
                maximum=maximum,
                deadline_monotonic=deadline,
                expected_content_type=(
                    "application/json" if expect_json else "application/octet-stream"
                ),
            )
        except urllib.error.HTTPError as exc:
            status_arrived_late = time.monotonic() >= deadline
            diagnostic = _read_rejection_diagnostic(exc, deadline_monotonic=deadline)
            if status_arrived_late:
                raise ContractError("control service response deadline exceeded") from None
            if (
                isinstance(exc.code, bool)
                or not isinstance(exc.code, int)
                or not 100 <= exc.code <= 599
            ):
                raise ContractError(
                    "control service rejection status is invalid"
                ) from None
            raise ContractError(
                "control service rejected the request "
                f"(HTTP {exc.code}; diagnostic_sha256_16={diagnostic})"
            ) from None
        except urllib.error.URLError as exc:
            raise ContractError(
                f"control service is unreachable ({type(exc.reason).__name__})"
            ) from None
        except ContractError:
            raise
        except (OSError, ValueError) as exc:
            raise ContractError(
                f"control service response failed ({type(exc).__name__})"
            ) from None
        if not expect_json:
            return payload

        value = decode_strict_json_bytes(payload, label="control service response")
        if time.monotonic() >= deadline:
            raise ContractError("control service response deadline exceeded")
        if value is None and allow_null:
            return None
        if not isinstance(value, dict):
            raise ContractError("control service JSON response must be an object")
        return value

    @staticmethod
    def _segment(value: str) -> str:
        if not isinstance(value, str) or RESOURCE_ID_RE.fullmatch(value) is None:
            raise ContractError("control client resource ID is invalid")
        return quote(value, safe="")

    def health(self) -> dict[str, Any]:
        return self._request("GET", "/v1/health", authenticated=False)

    def get_record(
        self, workspace_id: str, kind: str, record_id: str
    ) -> dict[str, Any]:
        path = f"/v1/workspaces/{self._segment(workspace_id)}/records/{self._segment(kind)}/{self._segment(record_id)}"
        return self._request("GET", path)

    def put_record(
        self,
        workspace_id: str,
        kind: str,
        record_id: str,
        payload: Any,
        *,
        expected_revision: int | None,
    ) -> dict[str, Any]:
        expected_revision = _optional_revision(expected_revision)
        path = f"/v1/workspaces/{self._segment(workspace_id)}/records/{self._segment(kind)}/{self._segment(record_id)}"
        return self._request(
            "PUT",
            path,
            json_body={"payload": payload, "expected_revision": expected_revision},
        )

    def put_artifact(
        self,
        workspace_id: str,
        content: bytes,
        *,
        media_type: str = "application/octet-stream",
        visibility: str = "operator",
    ) -> dict[str, Any]:
        if not isinstance(content, bytes) or len(content) > MAX_ARTIFACT_REQUEST:
            raise ContractError(
                "control client artifact must be bytes no larger than 64 MiB"
            )
        if not isinstance(visibility, str) or visibility not in {
            "viewer",
            "operator",
            "owner",
        }:
            raise ContractError("control client artifact visibility is invalid")
        if (
            not isinstance(media_type, str)
            or not 1 <= len(media_type) <= 128
            or any(not 0x21 <= ord(character) <= 0x7E for character in media_type)
        ):
            raise ContractError("control client artifact media type is invalid")
        if visibility == "viewer" and media_type != "application/json":
            raise ContractError("viewer-visible artifacts must use application/json")
        receipt = self._request(
            "PUT",
            f"/v1/workspaces/{self._segment(workspace_id)}/artifacts",
            raw_body=content,
            headers={
                "Content-Type": "application/octet-stream",
                "X-Artifact-Media-Type": media_type,
                "X-Artifact-Visibility": visibility,
            },
        )
        if (
            type(receipt) is not dict
            or receipt.get("sha256") != hashlib.sha256(content).hexdigest()
            or type(receipt.get("size")) is not int
            or receipt["size"] != len(content)
            or receipt.get("media_type") != media_type
            or receipt.get("visibility") != visibility
        ):
            raise ContractError("control client artifact receipt integrity failed")
        return receipt

    def get_artifact(self, workspace_id: str, digest: str) -> bytes:
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise ContractError("control client artifact digest is invalid")
        content = self._request(
            "GET",
            f"/v1/workspaces/{self._segment(workspace_id)}/artifacts/{self._segment(digest)}",
            maximum=MAX_ARTIFACT_RESPONSE,
            expect_json=False,
        )
        if type(content) is not bytes or hashlib.sha256(content).hexdigest() != digest:
            raise ContractError("control client artifact content integrity failed")
        return content

    def verify_audit(self, workspace_id: str) -> dict[str, Any]:
        return self._request(
            "GET", f"/v1/workspaces/{self._segment(workspace_id)}/audit/verify"
        )

    def revoke_token(self, workspace_id: str, token_id: str) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/v1/workspaces/{self._segment(workspace_id)}/tokens/{self._segment(token_id)}/revoke",
            json_body={},
        )

    def fleet_status(self, workspace_id: str) -> dict[str, Any]:
        return self._request(
            "GET", f"/v1/workspaces/{self._segment(workspace_id)}/fleet"
        )

    def enqueue_job(self, workspace_id: str, **job: Any) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/v1/workspaces/{self._segment(workspace_id)}/jobs",
            json_body=job,
        )

    def list_jobs(self, workspace_id: str) -> dict[str, Any]:
        return self._request(
            "GET", f"/v1/workspaces/{self._segment(workspace_id)}/jobs"
        )

    def get_job(self, workspace_id: str, job_id: str) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/v1/workspaces/{self._segment(workspace_id)}/jobs/{self._segment(job_id)}",
        )

    def cancel_job(self, workspace_id: str, job_id: str) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/v1/workspaces/{self._segment(workspace_id)}/jobs/{self._segment(job_id)}/cancel",
            json_body={},
        )

    def worker_lease(self, *, lease_seconds: int = 120) -> dict[str, Any] | None:
        lease_seconds = _lease_duration(lease_seconds, label="lease duration")
        return self._request(
            "POST",
            "/v1/workers/lease",
            json_body={"lease_seconds": lease_seconds},
            allow_null=True,
        )

    def worker_heartbeat(
        self, job_id: str, lease_token: str, *, extend_seconds: int = 120
    ) -> dict[str, Any]:
        lease_token = _lease_token(lease_token)
        extend_seconds = _lease_duration(extend_seconds, label="lease extension")
        return self._request(
            "POST",
            f"/v1/workers/jobs/{self._segment(job_id)}/heartbeat",
            json_body={"lease_token": lease_token, "extend_seconds": extend_seconds},
        )

    def worker_complete(
        self,
        job_id: str,
        lease_token: str,
        *,
        succeeded: bool,
        result: dict[str, Any],
    ) -> dict[str, Any]:
        lease_token = _lease_token(lease_token)
        if not isinstance(succeeded, bool):
            raise ContractError("control client completion success flag is invalid")
        if not isinstance(result, dict):
            raise ContractError("control client completion result must be an object")
        return self._request(
            "POST",
            f"/v1/workers/jobs/{self._segment(job_id)}/complete",
            json_body={
                "lease_token": lease_token,
                "succeeded": succeeded,
                "result": result,
            },
        )
