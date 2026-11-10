import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from stm.manifest import TrustStore  # noqa: E402
from stm.registry import Registry  # noqa: E402
from stm.runtime import AgentRuntime  # noqa: E402


class Clock:
    def __init__(self):
        self.t = 1_700_000_000

    def __call__(self):
        return self.t


def send_email_v1():
    return {"name": "send_email", "version": "1.0.0", "description": "Send an email to one recipient.",
            "inputSchema": {"type": "object", "additionalProperties": False,
                            "properties": {"to": {"type": "string", "maxLength": 254},
                                           "body": {"type": "string", "maxLength": 5000}},
                            "required": ["to", "body"]}}


def get_weather_v1():
    return {"name": "get_weather", "version": "1.0.0", "description": "Weather for a city.",
            "inputSchema": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}}


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def key():
    return Ed25519PrivateKey.generate()


@pytest.fixture
def registry(key, clock):
    r = Registry("acme", key, clock=clock)
    r.publish(send_email_v1())
    r.publish(get_weather_v1())
    return r


@pytest.fixture
def trust(key):
    t = TrustStore()
    t.add("acme", key.public_key())
    return t


@pytest.fixture
def sent():
    return []


@pytest.fixture
def runtime(trust, registry, clock, sent):
    handlers = {"send_email": lambda a: sent.append(a) or "sent", "get_weather": lambda a: {"temp_c": 20}}
    return AgentRuntime(trust, registry.fetch_definition, handlers, clock=clock)
