"""Read only the effective buffer settings from an owned fixture's trace."""
import io

from browser_core.live_trace import _open_shared_source
from browser_core.trace_rpc import _fields, _one, _read_varint, _repeated


def observed_buffers(path):
    with _open_shared_source(path) as source:
        prefix = source.read(4 * 1024 * 1024)
    stream = io.BytesIO(prefix)
    while stream.tell() < len(prefix):
        offset = stream.tell()
        assert _read_varint(stream) == 10, 'invalid owned trace envelope'
        size = _read_varint(stream)
        if size > len(prefix) - stream.tell():
            break
        packet = _fields(stream.read(size))
        configs = _repeated(packet, 33, 2)
        if not configs:
            continue
        assert len(configs) == 1
        rows = []
        for body in _repeated(_fields(configs[0]), 1, 2):
            config = _fields(body)
            rows.append({'size_kib': _one(config, 1, 0, 0),
                         'fill_policy': _one(config, 4, 0, 0),
                         'experimental_mode': _one(config, 8, 0, 0)})
        assert rows, 'owned trace has no buffer configuration'
        return {'trace_config_offset': offset, 'buffers': rows}
    raise AssertionError('effective configuration missing from bounded trace prefix')


def require_buffer_mode(config, expected):
    assert all(row['experimental_mode'] == expected for row in config['buffers']), \
        'effective trace is not using the expected buffer implementation'
