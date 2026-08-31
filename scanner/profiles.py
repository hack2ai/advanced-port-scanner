"""Reusable scan profiles for authorized network discovery."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanProfile:
    name: str
    start_port: int
    end_port: int
    description: str

    @property
    def port_range(self) -> str:
        return f"{self.start_port}-{self.end_port}"


SCAN_PROFILES: dict[str, ScanProfile] = {
    "quick": ScanProfile("quick", 1, 100, "Fast check of common low ports"),
    "standard": ScanProfile("standard", 1, 1024, "Common TCP service range"),
    "extended": ScanProfile("extended", 1, 10000, "Broader authorized service discovery"),
    "full": ScanProfile("full", 1, 65535, "Complete TCP port range; subject to configured limits"),
}


def get_profile(name: str) -> ScanProfile | None:
    return SCAN_PROFILES.get(name.strip().lower())


def list_profiles() -> list[dict[str, object]]:
    return [
        {
            "name": profile.name,
            "ports": profile.port_range,
            "description": profile.description,
        }
        for profile in SCAN_PROFILES.values()
    ]
