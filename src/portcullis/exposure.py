"""Exposure engine.

Classifies every service of a stack by how reachable it is (Internet, local
network, host only, internal), by crossing three signals:

* **published ports** - every ``ports:`` entry binds a host port; binding to
  a loopback address limits it to the host, anything else is reachable from
  the local network (and from the Internet if the router forwards the port);
* **reverse proxy routing** - a service routed by the reverse proxy
  (Traefik or caddy-docker-proxy labels in v0.1) is considered reachable
  from the Internet, since the proxy is typically the Internet entry point;
* **internal networks** - a service attached only to ``internal: true``
  networks has no gateway, so even published ports are unreachable.

The engine also flags services that *bypass* the reverse proxy: routed by
the proxy but additionally publishing a host port, which silently defeats
the authentication or TLS the proxy provides.
"""

from __future__ import annotations

from portcullis.model import Exposure, Service, Stack

TRAEFIK_ENABLE_LABEL = "traefik.enable"


def is_proxied(service: Service) -> bool:
    """True when the service is routed to the outside by a reverse proxy."""
    labels = service.labels
    if labels.get(TRAEFIK_ENABLE_LABEL, "").strip().lower() == "true":
        return True
    if any(key == "caddy" or key.startswith("caddy.") or key.startswith("caddy_")
           for key in labels):
        return True
    # nginx-proxy (jwilder) convention: routing driven by an env variable.
    return "VIRTUAL_HOST" in service.environment


def has_published_ports(service: Service) -> bool:
    return bool(service.ports)


def bypasses_proxy(service: Service) -> bool:
    """Routed through the reverse proxy *and* directly reachable via a host port."""
    return is_proxied(service) and any(not p.loopback_only for p in service.ports)


def classify_service(service: Service, stack: Stack) -> Exposure:
    if service.network_mode == "host":
        # Host networking: every port the app listens on is bound on every
        # host interface - reachable from the local network at least.
        return Exposure.INTERNET if is_proxied(service) else Exposure.LAN

    exposure = Exposure.INTERNAL

    if service.ports and not _only_internal_networks(service, stack):
        if any(not p.loopback_only for p in service.ports):
            exposure = Exposure.LAN
        else:
            exposure = Exposure.HOST

    if is_proxied(service):
        exposure = max(exposure, Exposure.INTERNET)

    return exposure


def classify(stack: Stack) -> dict[str, Exposure]:
    """Classify every service of the stack. Keyed by service name."""
    return {name: classify_service(service, stack) for name, service in stack.services.items()}


def _only_internal_networks(service: Service, stack: Stack) -> bool:
    """True when every network the service is attached to is ``internal: true``.

    Internal networks have no gateway: Docker cannot NAT published ports for
    them, so the service is unreachable from outside the container network.
    """
    if not service.networks:
        return False  # default bridge network is not internal
    known = [stack.networks.get(name) for name in service.networks]
    return all(network is not None and network.internal for network in known)
