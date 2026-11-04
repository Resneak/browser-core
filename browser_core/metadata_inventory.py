"""Bounded discovery of validated portable metadata, never inferred ownership."""
from collections import Counter, defaultdict

from .contracts import ContractError

ACTIVITIES = ('browser-control', 'page-evaluation', 'source-acquisition')
INVENTORY_LIMIT = 16
MAX_INVENTORY_CONTEXT_GROUPS = 8192
MAX_INVENTORY_API_GROUPS = 8192
MAX_INVENTORY_CONTEXT_API_GROUPS = 32768
MAX_INVENTORY_GROUP_LABEL_BYTES = 1024


def _bounded_label(value, label):
    if type(value) is not str:
        raise ContractError(f'inventory {label} is invalid')
    try:
        size = len(value.encode('utf-8'))
    except UnicodeEncodeError:
        raise ContractError(f'inventory {label} is invalid') from None
    if size > MAX_INVENTORY_GROUP_LABEL_BYTES:
        raise ContractError(f'inventory {label} exceeds byte limit')


def analyst_activity(value):
    if (not isinstance(value, (list, tuple)) or len(value) > len(ACTIVITIES)
            or any(not isinstance(item, str) or item not in ACTIVITIES for item in value)
            or len(set(value)) != len(value)):
        raise ContractError('analyst activity requires distinct documented activity names')
    return sorted(value)


class MetadataInventory:
    def __init__(self):
        self.contexts = Counter()
        self.kinds = Counter()
        self.apis = Counter()
        self.context_apis = defaultdict(Counter)
        self.context_api_groups = 0
        self.events = 0

    @staticmethod
    def validate_identity(event):
        execution = event.get('execution') or {}
        if any(key in execution and execution[key] is not None
               and type(execution[key]) is not str
               for key in ('context_id', 'frame_id', 'worker_id')):
            raise ContractError('inventory context identity is invalid')

    def add(self, event):
        self.validate_identity(event)
        execution = event.get('execution') or {}
        kind = 'worker' if execution.get('worker_id') else ('window' if execution.get('frame_id') else 'other')
        key = (event['process']['pid'], execution.get('context_id') or '',
               execution.get('frame_id') or '', execution.get('worker_id') or '', kind)
        api = event['event']['name']
        for identity in key[1:4]:
            _bounded_label(identity, 'context identity')
        _bounded_label(api, 'API name')
        pair_counts = self.context_apis.get(key)
        new_pair = pair_counts is None or api not in pair_counts
        if key not in self.contexts and len(self.contexts) >= MAX_INVENTORY_CONTEXT_GROUPS:
            raise ContractError('inventory contexts limit exceeded')
        if api not in self.apis and len(self.apis) >= MAX_INVENTORY_API_GROUPS:
            raise ContractError('inventory apis limit exceeded')
        if new_pair and self.context_api_groups >= MAX_INVENTORY_CONTEXT_API_GROUPS:
            raise ContractError('inventory context_apis limit exceeded')
        self.contexts[key] += 1
        self.kinds[kind] += 1
        self.apis[api] += 1
        self.context_apis[key][api] += 1
        if new_pair:
            self.context_api_groups += 1
        self.events += 1

    @staticmethod
    def _apis(counts, limit):
        rows = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]
        return {'total_groups': len(counts), 'reported_groups': len(rows),
                'truncated': len(counts) > len(rows),
                'groups': [{'api': key, 'events': str(count)} for key, count in rows]}

    def result(self, activities):
        rows = sorted(self.contexts.items(), key=lambda item: (-item[1], item[0]))[:INVENTORY_LIMIT]
        return {'schema': 'browser-core.metadata-inventory/1',
                'scope': 'all-matching-events-before-pagination',
                'matching_events': str(self.events),
                'context_kind_counts': {key: str(self.kinds[key]) for key in ('window', 'worker', 'other')},
                'contexts': {'total_groups': len(self.contexts), 'reported_groups': len(rows),
                    'truncated': len(rows) < len(self.contexts),
                    'groups': [{'pid': str(key[0]), 'context_id': key[1], 'frame_id': key[2],
                                'worker_id': key[3], 'kind': key[4], 'events': str(count),
                                'apis': self._apis(self.context_apis[key], 8)} for key, count in rows]},
                'apis': self._apis(self.apis, INVENTORY_LIMIT),
                'analyst_instrumentation': {'declared_activities': activities,
                    'declaration_source': 'caller', 'activity_presence': 'declared' if activities else 'unknown',
                    'event_ownership': 'unresolved', 'declaration_assigns_events': False},
                'context_identity_proves_process_isolation': False,
                'pid_is_recorded_renderer_identity_not_control_authority': True,
                'source_url_to_script_mapping_established': False}
