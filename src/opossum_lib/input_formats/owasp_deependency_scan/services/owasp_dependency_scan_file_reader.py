import logging
import uuid
from pathlib import Path

from opossum_lib.core.entities.metadata import Metadata
from opossum_lib.core.entities.opossum import Opossum
from opossum_lib.core.entities.scan_results import ScanResults
from opossum_lib.core.services.input_reader import InputReader


class OwaspDependencyScanFileReader(InputReader):
    path: Path

    def __init__(self, path: Path):
        self.path = path

    def read(self) -> Opossum:
        logging.info(f"Reading {self.path} as OWASP Dependency Scan")
        return Opossum(
            scan_results=ScanResults(
                metadata=Metadata(
                    build_date="now",
                    project_id=str(uuid.uuid4()),
                    project_title="OWASP Dependency Scan",
                    file_creation_date="now"
                ),
                resources= []
            )
        )

