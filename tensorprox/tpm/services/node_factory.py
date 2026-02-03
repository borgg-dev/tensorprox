"""Factory helpers to construct Nodes with provider-aware defaults."""
from __future__ import annotations

import json
from typing import Optional

from shared.config import TensorProxSettings
from shared.node import Node

from tensorprox.tpm.services.provider_registry import ProviderRegistry
from shared.models import ExitHubDeployRequest


class NodeFactory:
    """Build nodes with sane defaults per provider."""

    def __init__(self, settings: TensorProxSettings, registry: ProviderRegistry):
        self.settings = settings
        self.registry = registry

    def build_exit_hub_node(self, req: ExitHubDeployRequest) -> Node:
        """Construct an exit hub node with provider-aware defaults."""
        provider = req.cloud_provider or self.registry.default_provider
        region = req.region or self.registry.resolve_region(provider, None, None)
        self.registry.validate_region(provider, region)
        instance_type = self.registry.resolve_instance_type(provider, req.instance_type)
        ports_json = json.dumps(req.ports)

        return Node(
            node_type="exit_hub",
            region=region,
            instance_type=instance_type,
            cloud_provider=provider,
            ORIGIN_IP=req.origin_ip,
            ORIGIN_ID=req.origin_id,
            EMN_IP=req.emn_ip,
            PORTS_JSON=ports_json,
        )
