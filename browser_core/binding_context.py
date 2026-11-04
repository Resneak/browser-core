"""Native nearest-visible-JavaScript-frame evidence, distinct from API ownership.

The pinned V8 API filters frames by origin and skips non-JavaScript frames.
Its script number is the root script for eval/regexp, not necessarily the
immediate script number recorded elsewhere. No frame, worker or causal parent
is inferred from these identifiers.
"""
from __future__ import annotations

import re

from .errors import ContractError

JS_STACK_SCHEMA = 'browser-core.js-stack/1'
JS_STACK_COLUMNS = ('stack_context_schema', 'stack_context_status',
                    'stack_v8_context_id', 'stack_realm_id', 'stack_root_script_id')
OBSERVED_STACK_STATES = frozenset({'observed', 'limited-context'})
UNAVAILABLE_STACK_STATES = frozenset({'no-isolate', 'no-visible-js-frame', 'non-blink-context'})


def validate_js_stack(value: object) -> dict:
    """Validate the closed portable shape without upgrading limited evidence."""
    if not isinstance(value, dict) or value.get('schema') != JS_STACK_SCHEMA:
        raise ContractError('native JavaScript stack schema is invalid')
    status = value.get('status')
    expected = {'schema', 'status'}
    if isinstance(status, str) and status in OBSERVED_STACK_STATES:
        expected |= {'v8_context_id', 'realm_id', 'root_script_number'}
        token = value.get('v8_context_id')
        if (not isinstance(token, str) or re.fullmatch('[0-9A-F]{32}', token) is None
                or token == '0' * 32):
            raise ContractError('native JavaScript stack context token is invalid')
        for key, minimum in (('realm_id', 0), ('root_script_number', 1)):
            number = value.get(key)
            if type(number) is not int or not minimum <= number <= 2_147_483_647:
                raise ContractError('native JavaScript stack number is invalid')
    elif not isinstance(status, str) or status not in UNAVAILABLE_STACK_STATES:
        raise ContractError('native JavaScript stack status is invalid')
    if set(value) != expected:
        raise ContractError('native JavaScript stack fields are invalid')
    return value


def decode_js_stack(row: dict) -> dict | None:
    """Missing metadata is legacy absence; partial metadata is an error."""
    values = [row.get(key) for key in JS_STACK_COLUMNS]
    values = [None if value in (None, '', '[NULL]') else value for value in values]
    if all(value is None for value in values):
        return None
    schema, status, token, realm, script = values
    result = {'schema': schema, 'status': status}
    if any(value is not None for value in (token, realm, script)):
        try:
            if (not isinstance(realm, str) or not isinstance(script, str)
                    or re.fullmatch('0|[1-9][0-9]{0,9}', realm) is None
                    or re.fullmatch('[1-9][0-9]{0,9}', script) is None):
                raise ValueError
            result.update(v8_context_id=token, realm_id=int(realm), root_script_number=int(script))
        except (ValueError, TypeError):
            raise ContractError('native JavaScript stack columns are invalid') from None
    return validate_js_stack(result)

