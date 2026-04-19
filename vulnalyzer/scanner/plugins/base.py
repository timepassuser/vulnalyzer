from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar


@dataclass
class DependencyInfo:
    version: str
    source: str
    is_direct: bool
    is_dev: bool = False
    parent: str | None = None
    depth: int = 1
    dependency_path: list[str] | None = None


class ManifestPlugin:
    manifest_files: ClassVar[list[str]] = []
    ecosystem: ClassVar[str] = ""

    def parse(self, text: str) -> dict[str, DependencyInfo]:
        raise NotImplementedError

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} ecosystem={self.ecosystem!r}>"