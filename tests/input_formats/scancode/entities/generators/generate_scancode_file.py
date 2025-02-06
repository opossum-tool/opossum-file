# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections import defaultdict
from pathlib import PurePath
from typing import Any

from faker.providers import BaseProvider
from faker.providers.company import Provider as CompanyProvider
from faker.providers.date_time import Provider as DateProvider
from faker.providers.file import Provider as FileProvider
from faker.providers.internet import Provider as InternetProvider
from faker.providers.lorem.en_US import Provider as LoremProvider
from faker.providers.misc import Provider as MiscProvider

from opossum_lib.input_formats.scancode.entities.scancode_model import (
    CopyrightModel,
    EmailModel,
    ExtraDataModel,
    FileBasedLicenseDetectionModel,
    FileModel,
    FileTypeModel,
    GlobalLicenseDetectionModel,
    HeaderModel,
    HolderModel,
    MatchModel,
    OptionsModel,
    ReferenceMatchModel,
    ScancodeModel,
    SystemEnvironmentModel,
    UrlModel,
)
from tests.shared.generator_helpers import entry_or_none, random_list

type TempPathTree = dict[str, TempPathTree | None]


class ScanCodeDataProvider(BaseProvider):
    file_provider: FileProvider
    lorem_provider: LoremProvider
    date_provider: DateProvider
    misc_provider: MiscProvider
    internet_provider: InternetProvider
    company_provider: CompanyProvider

    def __init__(self, generator: Any):
        super().__init__(generator)
        self.file_provider = FileProvider(generator)
        self.lorem_provider = LoremProvider(generator)
        self.date_provider = DateProvider(generator)
        self.misc_provider = MiscProvider(generator)
        self.internet_provider = InternetProvider(generator)
        self.company_provider = CompanyProvider(generator)

    def scancode_data(
        self,
        *,
        dependencies: list | None = None,
        files: list[FileModel] | None = None,
        license_detections: list[GlobalLicenseDetectionModel] | None = None,
        headers: list[HeaderModel] | None = None,
        packages: list | None = None,
        options: OptionsModel | None = None,
    ) -> ScancodeModel:
        # TODO: #184 depending on which options are passed in additional_options
        # we need to generate different fields, e.g. --licenses
        # out of scope for now
        files = files or self.files()
        license_detections = license_detections or self.global_license_detections(files)
        if headers is None:
            headers = [self.header(options=options)]
        return ScancodeModel(
            dependencies=dependencies or [],
            files=files,
            license_detections=license_detections,
            headers=headers,
            packages=packages or [],
        )

    def header(
        self,
        *,
        duration: float | None = None,
        end_timestamp: str | None = None,
        errors: list | None = None,
        extra_data: ExtraDataModel | None = None,
        message: Any | None = None,
        notice: str | None = None,
        options: OptionsModel | None = None,
        output_format_version: str | None = None,
        start_timestamp: str | None = None,
        tool_name: str | None = None,
        tool_version: str | None = None,
        warnings: list | None = None,
    ) -> HeaderModel:
        return HeaderModel(
            duration=duration or self.random_int(max=9999999) / 1e3,
            end_timestamp=end_timestamp or self.date_provider.iso8601(),
            errors=errors or [],
            extra_data=extra_data or self.extra_data(),
            message=message,
            notice=notice or "Generated with ScanCode and provided...",
            options=options or self.options(),
            output_format_version=output_format_version or "4.0.0",
            start_timestamp=start_timestamp or self.date_provider.iso8601(),
            tool_name=tool_name or "scancode-toolkit",
            tool_version=tool_version or "v32.3.0-20-g93ca65c34e",
            warnings=warnings or [],
        )

    def options(
        self, *, input: list[str] | None = None, **additional_options: Any
    ) -> OptionsModel:
        return OptionsModel(
            input=input
            or [
                self.file_provider.file_path(
                    depth=self.random_int(min=1, max=5), absolute=True, extension=""
                )
            ],
            **additional_options,
        )

    def extra_data(
        self,
        *,
        files_count: int | None = None,
        spdx_license_list_version: str | None = None,
        system_environment: SystemEnvironmentModel | None = None,
    ) -> ExtraDataModel:
        return ExtraDataModel(
            files_count=files_count or self.random_int(),
            spdx_license_list_version=spdx_license_list_version
            or self.numerify("#.##"),
            system_environment=system_environment or self.system_environment(),
        )

    def system_environment(
        self,
        *,
        cpu_architecture: str | None = None,
        operating_system: str | None = None,
        platform: str | None = None,
        platform_version: str | None = None,
        python_version: str | None = None,
    ) -> SystemEnvironmentModel:
        operating_system = operating_system or self.random_element(
            ["linux", "windows", "macos"]
        )
        return SystemEnvironmentModel(
            cpu_architecture=cpu_architecture or self.random_element(["32", "64"]),
            operating_system=operating_system,
            platform=platform
            or operating_system + self.numerify("-##.###.####-generic"),
            platform_version=platform_version or "#" + self.numerify("###"),
            python_version=python_version or self.numerify("#.##.###"),
        )

    def global_license_detections(
        self, files: list[FileModel]
    ) -> list[GlobalLicenseDetectionModel]:
        license_counter: dict[str, int] = defaultdict(int)
        id_to_license_detection: dict[str, FileBasedLicenseDetectionModel] = {}
        for file in files:
            if not file.license_detections:
                continue
            for ld in file.license_detections:
                license_counter[ld.identifier] += 1
                id_to_license_detection[ld.identifier] = ld

        global_license_detections = []
        for id, count in license_counter.items():
            ld = id_to_license_detection[id]
            gld = GlobalLicenseDetectionModel(
                detection_count=count,
                license_expression=ld.license_expression,
                license_expression_spdx=ld.license_expression_spdx,
                identifier=ld.identifier,
                reference_matches=[
                    ReferenceMatchModel(
                        end_line=match.end_line,
                        from_file=match.from_file,
                        license_expression=match.license_expression,
                        license_expression_spdx=match.license_expression_spdx,
                        matched_length=match.matched_length,
                        matcher=match.matcher,
                        match_coverage=match.match_coverage,
                        rule_identifier=match.rule_identifier,
                        rule_relevance=match.rule_relevance,
                        rule_url=match.rule_url,
                        score=match.score,
                        start_line=match.start_line,
                    )
                    for match in ld.matches
                ],
            )
            global_license_detections.append(gld)
        return global_license_detections

    def generate_path_structure(
        self,
        depth: int = 3,
        max_folders_per_level: int = 3,
        max_files_per_level: int = 3,
    ) -> TempPathTree:
        num_files = self.random_int(0, max_files_per_level)
        files: TempPathTree = {
            self.file_provider.file_name(category="text"): None
            for _ in range(num_files)
        }
        if depth == 0:
            return files
        else:
            num_folders = self.random_int(0, max_folders_per_level)
            folders = {}
            for _ in range(num_folders):
                folder_name = self.lorem_provider.word()
                children = self.generate_path_structure(
                    depth=depth - 1,
                    max_files_per_level=max_files_per_level,
                    max_folders_per_level=max_folders_per_level,
                )
                folders[folder_name] = children
            return {**files, **folders}

    def files(self, path_tree: TempPathTree | None = None) -> list[FileModel]:
        path_tree = path_tree or self.generate_path_structure()

        def process_path(current_path: str, path_tree: TempPathTree) -> list[FileModel]:
            files: list[FileModel] = []
            for name, data in path_tree.items():
                path = current_path + name
                if data:
                    child_files = process_path(path + "/", data)
                    child_types = [c.type for c in child_files]
                    folder = self.single_folder(
                        path=path,
                        dirs_count=child_types.count(FileTypeModel.DIRECTORY),
                        files_count=child_types.count(FileTypeModel.FILE),
                        size_count=sum(c.size or 0 for c in child_files),
                    )
                    files.append(folder)
                    files.extend(child_files)
                else:
                    file = self.single_file(
                        path=path,
                    )
                    files.append(file)
            return files

        return process_path("", path_tree=path_tree)

    def single_folder(
        self,
        *,
        path: str,
        authors: list | None = None,
        base_name: str | None = None,
        copyrights: list[CopyrightModel] | None = None,
        date: str | None = None,
        detected_license_expression: str | None = None,
        detected_license_expression_spdx: str | None = None,
        dirs_count: int = 0,
        emails: list[EmailModel] | None = None,
        extension: str = "",
        files_count: int = 0,
        file_type: str | None = None,
        for_packages: list | None = None,
        holders: list[HolderModel] | None = None,
        is_archive: bool = False,
        is_binary: bool = False,
        is_media: bool = False,
        is_script: bool = False,
        is_source: bool = False,
        is_text: bool = False,
        license_clues: list | None = None,
        license_detections: list[FileBasedLicenseDetectionModel] | None = None,
        md5: str | None = None,
        mime_type: str | None = None,
        name: str | None = None,
        package_data: list | None = None,
        percentage_of_license_text: float = 0.0,
        programming_language: str | None = None,
        scan_errors: list | None = None,
        sha1: str | None = None,
        sha256: str | None = None,
        size: int = 0,
        size_count: int = 0,
        urls: list[UrlModel] | None = None,
    ) -> FileModel:
        return FileModel(
            authors=authors or [],
            base_name=base_name or PurePath(PurePath(path).name).stem,
            copyrights=copyrights or [],
            date=date,
            detected_license_expression=detected_license_expression,
            detected_license_expression_spdx=detected_license_expression_spdx,
            dirs_count=dirs_count,
            emails=emails or [],
            extension=extension,
            files_count=files_count,
            file_type=file_type,
            for_packages=for_packages or [],
            holders=holders or [],
            is_archive=is_archive,
            is_binary=is_binary,
            is_media=is_media,
            is_script=is_script,
            is_source=is_source,
            is_text=is_text,
            license_clues=license_clues or [],
            license_detections=license_detections or [],
            md5=md5,
            mime_type=mime_type,
            name=name or PurePath(path).name,
            package_data=package_data or [],
            path=path,
            percentage_of_license_text=percentage_of_license_text,
            programming_language=programming_language,
            scan_errors=scan_errors or [],
            sha1=sha1,
            sha256=sha256,
            size=size,
            size_count=size_count,
            type=FileTypeModel.DIRECTORY,
            urls=urls or [],
        )

    def single_file(
        self,
        *,
        path: str,
        authors: list | None = None,
        base_name: str | None = None,
        copyrights: list[CopyrightModel] | None = None,
        date: str | None = None,
        detected_license_expression: str | None = None,
        detected_license_expression_spdx: str | None = None,
        dirs_count: int = 0,
        emails: list[EmailModel] | None = None,
        extension: str | None = None,
        files_count: int = 0,
        file_type: str | None = None,
        for_packages: list | None = None,
        holders: list[HolderModel] | None = None,
        is_archive: bool | None = None,
        is_binary: bool | None = None,
        is_media: bool | None = None,
        is_script: bool | None = None,
        is_source: bool | None = None,
        is_text: bool | None = None,
        license_clues: list | None = None,
        license_detections: list[FileBasedLicenseDetectionModel] | None = None,
        md5: str | None = None,
        mime_type: str | None = None,
        name: str | None = None,
        package_data: list | None = None,
        percentage_of_license_text: float | None = None,
        programming_language: str | None = None,
        scan_errors: list | None = None,
        sha1: str | None = None,
        sha256: str | None = None,
        size: int | None = None,
        size_count: int = 0,
        urls: list[UrlModel] | None = None,
    ) -> FileModel:
        if copyrights is None and holders is None:
            holders = []
            for _ in range(self.random_int(max=3)):
                start_line = self.random_int()
                end_line = start_line + self.random_int(max=2)
                holder = HolderModel(
                    holder=self.company_provider.company(),
                    start_line=start_line,
                    end_line=end_line,
                )
                holders.append(holder)
        if copyrights is None:
            assert holders is not None  # can never trigger but makes mypy happy
            copyrights = [
                CopyrightModel(
                    copyright="Copyright " + h.holder,
                    start_line=h.start_line,
                    end_line=h.end_line,
                )
                for h in holders
            ]
        if holders is None:
            holders = [
                HolderModel(
                    holder=cr.copyright,
                    start_line=cr.start_line,
                    end_line=cr.end_line,
                )
                for cr in copyrights
            ]
        license_detections = (
            license_detections
            if license_detections is not None
            else random_list(
                self,
                lambda: self.license_detection(path=path),
            )
        )
        detected_license_expression = detected_license_expression or " and ".join(
            ld.license_expression for ld in license_detections
        )
        detected_license_expression_spdx = detected_license_expression_spdx or "|".join(
            ld.license_expression_spdx for ld in license_detections
        )
        if emails is None:
            emails = random_list(self, self.email)
        if file_type is None:
            file_type = " ".join(self.lorem_provider.words())
        is_archive = (
            is_archive if is_archive is not None else self.misc_provider.boolean()
        )
        is_binary = is_binary if is_binary is not None else self.misc_provider.boolean()
        is_media = is_media if is_media is not None else self.misc_provider.boolean()
        is_script = is_script if is_script is not None else self.misc_provider.boolean()
        is_source = is_source if is_source is not None else self.misc_provider.boolean()
        is_text = is_text if is_text is not None else self.misc_provider.boolean()
        mime_type = (
            mime_type if mime_type is not None else str(self.misc_provider.md5())
        )
        if percentage_of_license_text is None:
            percentage_of_license_text = self.random_int(max=10**5) / 10**5
        if programming_language is None:
            programming_language = entry_or_none(
                self.misc_provider,
                self.random_element(["Java", "Typescript", "HTML", "Python"]),
            )
        return FileModel(
            authors=authors or [],
            base_name=base_name or PurePath(PurePath(path).name).stem,
            copyrights=copyrights,
            date=date or self.date_provider.iso8601(),
            detected_license_expression=detected_license_expression,
            detected_license_expression_spdx=detected_license_expression_spdx,
            dirs_count=dirs_count,
            emails=emails,
            extension=extension or PurePath(path).suffix,
            files_count=files_count,
            file_type=file_type,
            for_packages=for_packages or [],
            holders=holders,
            is_archive=is_archive,
            is_binary=is_binary,
            is_media=is_media,
            is_script=is_script,
            is_source=is_source,
            is_text=is_text,
            license_clues=license_clues or [],
            license_detections=license_detections,
            md5=md5 if md5 is not None else self.misc_provider.md5(),
            mime_type=mime_type,
            name=name or PurePath(path).name,
            package_data=package_data or [],
            path=path,
            percentage_of_license_text=percentage_of_license_text,
            programming_language=programming_language,
            scan_errors=scan_errors or [],
            sha1=sha1 if sha1 is not None else self.misc_provider.sha1(),
            sha256=sha256 if sha256 is not None else self.misc_provider.sha256(),
            size=size if size is not None else self.random_int(max=10**9),
            size_count=size_count,
            type=FileTypeModel.FILE,
            urls=urls if urls is not None else random_list(self, self.url),
        )

    def copyright(
        self,
        copyright: str | None = None,
        end_line: int | None = None,
        start_line: int | None = None,
    ) -> CopyrightModel:
        start_line = start_line or self.random_int()
        end_line = start_line + self.random_int(max=50)
        return CopyrightModel(
            copyright=copyright or "Copyright " + self.company_provider.company(),
            end_line=end_line,
            start_line=start_line,
        )

    def email(
        self,
        email: str | None = None,
        end_line: int | None = None,
        start_line: int | None = None,
    ) -> EmailModel:
        start_line = start_line or self.random_int()
        end_line = start_line + self.random_int(max=2)
        return EmailModel(
            email=email or self.internet_provider.email(),
            end_line=end_line,
            start_line=start_line,
        )

    def url(
        self,
        url: str | None = None,
        end_line: int | None = None,
        start_line: int | None = None,
    ) -> UrlModel:
        start_line = start_line or self.random_int()
        end_line = start_line + self.random_int(max=2)
        return UrlModel(
            url=url or self.internet_provider.url(),
            end_line=end_line,
            start_line=start_line,
        )

    def license_detection(
        self,
        license_expression: str | None = None,
        license_expression_spdx: str | None = None,
        matches: list[MatchModel] | None = None,
        identifier: str | None = None,
        path: str | None = None,
    ) -> FileBasedLicenseDetectionModel:
        if path is None and matches is None:
            raise RuntimeError(
                "Neither path nor matches given which is likely a user error. "
                + "To generate a LicenseDetection without matches pass "
                + "an empty list for matches."
            )
        license_expression_spdx = license_expression_spdx or self.random_element(
            ["Apache-2.0", "MIT", "GPL", "LGPL", "CC0"]
        )
        license_expression = license_expression or license_expression_spdx.lower()
        identifier = identifier or license_expression.replace("-", "_").replace(
            ".", "_"
        ) + "-" + str(self.misc_provider.uuid4(cast_to=str))
        matches = matches or random_list(
            self,
            lambda: self.match(
                from_file=str(path),
                license_expression=license_expression,
                license_expression_spdx=license_expression_spdx,
                rule_identifier="rule-" + identifier,
            ),
            min_number_of_entries=1,
        )
        return FileBasedLicenseDetectionModel(
            license_expression=license_expression,
            license_expression_spdx=license_expression_spdx,
            matches=matches,
            identifier=identifier,
        )

    def match(
        self,
        *,
        end_line: int | None = None,
        from_file: str,
        license_expression: str | None = None,
        license_expression_spdx: str | None = None,
        matched_length: int | None = None,
        matcher: str | None = None,
        match_coverage: float | None = None,
        rule_identifier: str | None = None,
        rule_relevance: int | None = None,
        rule_url: Any | None = None,
        score: float | None = None,
        start_line: int | None = None,
    ) -> MatchModel:
        start_line = start_line or self.random_int()
        end_line = start_line + self.random_int()
        if license_expression_spdx is None:
            license_expression_spdx = self.lexify("???? License")
        return MatchModel(
            end_line=end_line,
            from_file=from_file,
            license_expression=license_expression or "",
            license_expression_spdx=license_expression_spdx or "",
            matched_length=matched_length or self.random_int(),
            matcher=matcher or self.bothify("#-???-??"),
            match_coverage=match_coverage or float(self.random_int(max=100)),
            rule_identifier=rule_identifier
            or "-".join(self.lorem_provider.words(nb=5)),
            rule_relevance=rule_relevance or self.random_int(max=100),
            rule_url=rule_url or self.internet_provider.url(),
            score=score or float(self.random_int(max=100)),
            start_line=start_line,
        )
