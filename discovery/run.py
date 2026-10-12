import os
import time

import docker
import httpx
from docker.errors import DockerException

API_URL = os.getenv("ASPM_API_URL", "http://api:8000").rstrip("/")
API_KEY = os.getenv("ASPM_API_KEY", "")
DISCOVERY_INTERVAL_MINUTES = float(os.getenv("DISCOVERY_INTERVAL_MINUTES", "15"))
SOURCE_LABEL = "org.opencontainers.image.source"


def list_containers() -> list[dict]:
    client = docker.from_env()
    try:
        containers = client.containers.list(filters={"label": "aspm.environment"})
        return [
            {
                "name": c.name,
                "image": c.attrs["Config"]["Image"],
                "labels": {
                    k: v for k, v in c.labels.items() if k.startswith("aspm.") or k == SOURCE_LABEL
                },
            }
            for c in containers
        ]
    finally:
        client.close()


def discover() -> None:
    try:
        assets = list_containers()
    except DockerException:
        return
    try:
        httpx.post(
            f"{API_URL}/assets/discover",
            json={"source": "docker", "assets": assets},
            headers={"X-API-Key": API_KEY},
            timeout=30,
        )
    except httpx.HTTPError:
        pass


def main() -> None:
    if not API_KEY:
        raise SystemExit("ASPM_API_KEY is not set")
    while True:
        discover()
        time.sleep(DISCOVERY_INTERVAL_MINUTES * 60)


if __name__ == "__main__":
    main()
