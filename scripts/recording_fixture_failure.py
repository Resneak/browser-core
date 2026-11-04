"""Preflight for intentionally interrupted recording fixtures."""
from browser_core.errors import ContractError


def require_supported_failure_mode(mode):
    if mode == 'service-crash':
        raise ContractError(
            'service-crash fixture is disabled: PID-selected child termination '
            'does not establish ownership; use a reviewed owned fault mechanism')
    if mode not in ('finish', 'limit', 'forced'):
        raise ContractError('recording failure mode is invalid')


def interrupt_owned_tracing_service(document, session):
    # Preserve a fail-closed entry point for old callers. Do not inspect the
    # document, query host processes or terminate a PID-selected child.
    require_supported_failure_mode('service-crash')
