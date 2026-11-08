"""Business catalog (rr E-05 业务目录 schema、资源身份与不可变快照).

Loaded once per epoch by the unprivileged engine; it is not part of the spawner's start-up catalog. Every
object is strict JSON with a closed field set; any defect refuses start-up, so there is no partly usable
catalog. Documents become immutable in-memory snapshots read through openat2 beneath a trusted document root;
nothing reopens a path after start-up. IDs are logical names compared byte for byte, never paths or URLs.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from typing import Any, Mapping, Union

from .startup import ID, StartupRefused, _digest, _strict

CATALOG_BYTES_MAX = 1 << 20      # the catalog plus every descriptor it references
DESCRIPTORS_MAX = 128
PROVIDERS_MAX = 16
DOCUMENT_MAX = 256 * 1024
DOCUMENTS_TOTAL_MAX = 4 << 20
MODEL_INPUT_MAX, MODEL_TOKENS_MAX, MODEL_OUTPUT_MAX = 48 * 1024, 4096, 256 * 1024
TEXT_PLAIN = 'text/plain; charset=utf-8'
CHAT_PATH = '/v1/chat/completions'
HOST = re.compile(r'(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*')
DIGEST = re.compile(r'sha256:[0-9a-f]{64}')

SYS_OPENAT2 = 437                # one number on every Linux architecture (unified syscall table)
RESOLVE_NO_XDEV, RESOLVE_NO_MAGICLINKS, RESOLVE_NO_SYMLINKS, RESOLVE_BENEATH = 0x01, 0x02, 0x04, 0x08


class OpenHow(ctypes.Structure):
    _fields_ = [('flags', ctypes.c_uint64), ('mode', ctypes.c_uint64), ('resolve', ctypes.c_uint64)]


@dataclass(frozen=True, eq=False)
class ProviderConfig:
    provider_config_id: str
    adapter_kind: str
    wire_profile: str
    scheme: str
    host: str
    port: int
    path: str
    ip: str
    model_id: str
    credential_ref: str
    credential_version_ref: str
    provider_partition_id: str
    state_mode: str
    deployment_evidence_ref: str


@dataclass(frozen=True, eq=False)
class DocumentResource:
    resource_id: str
    descriptor_id: str
    descriptor_digest: str
    source_ref: str
    content_identity: str
    byte_length: int
    blob: bytes                  # the snapshot read at start-up; the only content any request sees
    allowed_actions: tuple[str, ...] = ('document.read',)


@dataclass(frozen=True, eq=False)
class ModelResource:
    resource_id: str
    descriptor_id: str
    descriptor_digest: str
    provider: ProviderConfig
    max_input_bytes: int
    max_output_tokens: int
    max_output_bytes: int
    allowed_actions: tuple[str, ...] = ('model.generate',)


Resource = Union[DocumentResource, ModelResource]


@dataclass(frozen=True)
class BusinessCatalog:
    business_catalog_digest: str
    resources: Mapping[str, Resource]


def _object(value: Any, keys: set[str], what: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise StartupRefused(f'{what}: fields must be exactly {sorted(keys)}')
    return value


def _id(value: Any, what: str) -> str:
    if type(value) is not str or not ID.fullmatch(value):
        raise StartupRefused(f'{what}: not an ID')
    return value


def _count(value: Any, high: int, what: str) -> int:
    if type(value) is not int or not 0 < value <= high:
        raise StartupRefused(f'{what}: not an integer in 1–{high}')
    return value


def _source_ref(value: Any) -> str:
    if (type(value) is not str or not value or value.startswith('/') or '\x00' in value
            or any(part in ('', '.', '..') for part in value.split('/'))):
        raise StartupRefused('source_ref must be a plain relative path')
    return value


def _artifact(root: Path, ref: str, digest: str, budget: list[int]) -> tuple[bytes, Any]:
    if type(digest) is not str or not DIGEST.fullmatch(digest):
        raise StartupRefused(f'{ref}: malformed digest')
    data = (root / _source_ref(ref)).read_bytes()
    budget[0] += len(data)
    if budget[0] > CATALOG_BYTES_MAX:
        raise StartupRefused('business catalog and descriptors exceed 1 MiB')
    if _digest(data) != digest:
        raise StartupRefused(f'{ref}: digest mismatch')
    return data, _strict(data)


def read_beneath(root_fd: int, source_ref: str, length: int) -> bytes:
    """openat2 beneath the document root, no symlinks, magic links or mount crossings; a regular file of
    exactly ``length`` bytes. Any unsupported call, type or size refuses."""
    libc = ctypes.CDLL(None, use_errno=True)
    how = OpenHow(os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, 0,
                  RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV)
    fd = libc.syscall(SYS_OPENAT2, root_fd, source_ref.encode(), ctypes.byref(how), ctypes.sizeof(how))
    if fd < 0:
        raise StartupRefused(f'{source_ref}: openat2 failed (errno {ctypes.get_errno()})')
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size != length:
            raise StartupRefused(f'{source_ref}: not a regular file of the declared length')
        data = b''
        while len(data) <= length:
            chunk = os.read(fd, length + 1 - len(data))
            if not chunk:
                break
            data += chunk
        if len(data) != length:
            raise StartupRefused(f'{source_ref}: read length differs from the declared length')
        return data
    finally:
        os.close(fd)


def _provider(body: Any) -> ProviderConfig:
    keys = {'provider_config_id', 'adapter_kind', 'wire_profile', 'endpoint', 'model_id', 'credential_ref',
            'credential_version_ref', 'provider_partition_id', 'state_mode', 'deployment_evidence_ref'}
    b = _object(body, keys, 'ProviderConfig')
    e = _object(b['endpoint'], {'scheme', 'host', 'port', 'path', 'ip'}, 'endpoint')
    if (b['adapter_kind'] != 'chat-tools-sse' or b['wire_profile'] not in ('chat-tools-core', 'llama-chat-tools')
            or b['state_mode'] != 'stateless_completion'):
        raise StartupRefused('ProviderConfig: unsupported adapter, profile or state mode')
    if (e['scheme'] not in ('http', 'https') or type(e['host']) is not str or not HOST.fullmatch(e['host'])
            or e['path'] != CHAT_PATH or type(e['ip']) is not str):
        raise StartupRefused('ProviderConfig: invalid endpoint')
    _count(e['port'], 65535, 'endpoint.port')
    try:
        ip = ipaddress.ip_address(e['ip'])
    except ValueError:
        raise StartupRefused('ProviderConfig: endpoint ip is not an address literal') from None
    if e['scheme'] == 'http' and not ip.is_loopback:
        raise StartupRefused('ProviderConfig: plain http only to a loopback model instance')
    # minimal: no credential store in this build, so only unauthenticated instances; a secret version joins
    # with the real connector (P2b).
    if b['credential_ref'] != 'none' or b['credential_version_ref'] != 'none':
        raise StartupRefused('ProviderConfig: only credential "none" is supported in this build')
    for key in ('provider_config_id', 'model_id', 'provider_partition_id', 'deployment_evidence_ref'):
        _id(b[key], f'ProviderConfig.{key}')
    return ProviderConfig(b['provider_config_id'], b['adapter_kind'], b['wire_profile'], e['scheme'], e['host'],
                          e['port'], e['path'], e['ip'], b['model_id'], b['credential_ref'],
                          b['credential_version_ref'], b['provider_partition_id'], b['state_mode'],
                          b['deployment_evidence_ref'])


def load_business(root: Path, name: str) -> BusinessCatalog:
    try:
        budget = [0]
        data = (root / _source_ref(name)).read_bytes()
        budget[0] = len(data)
        catalog = _object(_strict(data), {'document_root', 'resource_descriptor_refs', 'provider_config_refs'},
                          'BusinessCatalog')
        refs, provider_refs = catalog['resource_descriptor_refs'], catalog['provider_config_refs']
        if (type(refs) is not list or len(refs) > DESCRIPTORS_MAX or type(provider_refs) is not list
                or len(provider_refs) > PROVIDERS_MAX):
            raise StartupRefused('BusinessCatalog: reference lists missing or over their limits')
        providers: dict[str, ProviderConfig] = {}
        for entry in provider_refs:
            entry = _object(entry, {'artifact_ref', 'artifact_digest'}, 'provider_config_refs[]')
            config = _provider(_artifact(root, entry['artifact_ref'], entry['artifact_digest'], budget)[1])
            if config.provider_config_id in providers:
                raise StartupRefused(f'duplicate provider config {config.provider_config_id}')
            providers[config.provider_config_id] = config
        root_fd = os.open(root / _source_ref(catalog['document_root']),
                          os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            resources = _resources(root, refs, providers, root_fd, budget)
        finally:
            os.close(root_fd)
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise StartupRefused(f'business catalog unreadable: {error!r}') from None
    return BusinessCatalog(_digest(data), MappingProxyType(resources))


def _resources(root: Path, refs: list[Any], providers: dict[str, ProviderConfig], root_fd: int,
               budget: list[int]) -> dict[str, Resource]:
    resources: dict[str, Resource] = {}
    descriptor_ids: set[str] = set()
    documents = 0
    used_providers: set[str] = set()
    for entry in refs:
        entry = _object(entry, {'descriptor_ref', 'descriptor_digest'}, 'resource_descriptor_refs[]')
        digest = entry['descriptor_digest']
        _, body = _artifact(root, entry['descriptor_ref'], digest, budget)
        kind = body.get('kind') if type(body) is dict else None
        if kind == 'engine_local':
            b = _object(body, {'resource_id', 'descriptor_id', 'kind', 'allowed_actions', 'source_ref',
                               'content_identity', 'byte_length', 'media_type'}, 'DocumentDescriptor')
            if b['allowed_actions'] != ['document.read'] or b['media_type'] != TEXT_PLAIN:
                raise StartupRefused('DocumentDescriptor: actions or media type')
            if type(b['content_identity']) is not str or not DIGEST.fullmatch(b['content_identity']):
                raise StartupRefused('DocumentDescriptor: content_identity')
            length = b['byte_length']
            if type(length) is not int or not 0 <= length <= DOCUMENT_MAX:
                raise StartupRefused('DocumentDescriptor: byte_length outside 0–256 KiB')
            documents += length
            if documents > DOCUMENTS_TOTAL_MAX:
                raise StartupRefused('document snapshots exceed 4 MiB')
            blob = read_beneath(root_fd, _source_ref(b['source_ref']), length)
            blob.decode('utf-8')   # strict; a lone surrogate or bad byte raises
            if blob.startswith(b'\xef\xbb\xbf') or _digest(blob) != b['content_identity']:
                raise StartupRefused(f'{b["source_ref"]}: content does not match content_identity')
            resource: Resource = DocumentResource(_id(b['resource_id'], 'resource_id'),
                                                  _id(b['descriptor_id'], 'descriptor_id'), digest,
                                                  b['source_ref'], b['content_identity'], length, blob)
        elif kind == 'model':
            b = _object(body, {'resource_id', 'descriptor_id', 'kind', 'allowed_actions', 'provider_config_ref',
                               'max_input_bytes', 'max_output_tokens', 'max_output_bytes'}, 'ModelDescriptor')
            provider = providers.get(b['provider_config_ref'])
            if b['allowed_actions'] != ['model.generate'] or provider is None:
                raise StartupRefused('ModelDescriptor: actions or unresolved provider_config_ref')
            used_providers.add(provider.provider_config_id)
            resource = ModelResource(_id(b['resource_id'], 'resource_id'), _id(b['descriptor_id'], 'descriptor_id'),
                                     digest, provider,
                                     _count(b['max_input_bytes'], MODEL_INPUT_MAX, 'max_input_bytes'),
                                     _count(b['max_output_tokens'], MODEL_TOKENS_MAX, 'max_output_tokens'),
                                     _count(b['max_output_bytes'], MODEL_OUTPUT_MAX, 'max_output_bytes'))
        else:
            raise StartupRefused('descriptor kind must be engine_local or model')
        if resource.resource_id in resources or resource.descriptor_id in descriptor_ids:
            raise StartupRefused(f'duplicate resource or descriptor id {resource.resource_id}')
        resources[resource.resource_id] = resource
        descriptor_ids.add(resource.descriptor_id)
    if used_providers != set(providers):
        raise StartupRefused('a provider config is not referenced by any model descriptor')
    return resources
