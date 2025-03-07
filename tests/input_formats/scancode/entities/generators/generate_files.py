# SPDX-FileCopyrightText: TNG Technology Consulting GmbH <https://www.tngtech.com>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os.path
from pathlib import PurePath
from typing import Any

from faker.providers import BaseProvider
from faker.providers.company import Provider as CompanyProvider
from faker.providers.date_time import Provider as DateProvider
from faker.providers.file import Provider as FileProvider
from faker.providers.internet import Provider as InternetProvider
from faker.providers.lorem.en_US import Provider as LoremProvider
from faker.providers.misc import Provider as MiscProvider
from packageurl import PackageURL

from opossum_lib.input_formats.scancode.entities.scancode_model import (
    CopyrightModel,
    DependencyModel,
    EmailModel,
    FileBasedLicenseDetectionModel,
    FileModel,
    FileTypeModel,
    HolderModel,
    MatchModel,
    OptionsModel,
    PackageDataModel,
    UrlModel,
)
from tests.shared.generator_helpers import entry_or_none, random_bool, random_list

type TempPathTree = dict[str, TempPathTree | None]


class ScanCodeFileProvider(BaseProvider):
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

    def files(
        self, options: OptionsModel, path_tree: TempPathTree | None = None
    ) -> list[FileModel]:
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
                        options=options,
                    )
                    files.append(folder)
                    files.extend(child_files)
                else:
                    file = self.single_file(path=path, options=options)
                    files.append(file)
            return files

        return process_path("", path_tree=path_tree)

    def single_folder(
        self,
        *,
        path: str,
        options: OptionsModel,
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
        if options is None:
            options = self.options()
        path = self._convert_to_scancode_path(path, options)
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
        options: OptionsModel,
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
        for_packages: list[str] | None = None,
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
        package_data: list[PackageDataModel] | None = None,
        percentage_of_license_text: float | None = None,
        programming_language: str | None = None,
        scan_errors: list | None = None,
        sha1: str | None = None,
        sha256: str | None = None,
        size: int | None = None,
        size_count: int = 0,
        urls: list[UrlModel] | None = None,
    ) -> FileModel:
        path = self._convert_to_scancode_path(path, options)
        if options.copyright:
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
        if options.license:
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
            detected_license_expression_spdx = (
                detected_license_expression_spdx
                or "|".join(ld.license_expression_spdx for ld in license_detections)
            )
        if options.email and emails is None:
            emails = random_list(self, self.sc_email)
        if options.info:
            if file_type is None:
                file_type = " ".join(self.lorem_provider.words())
            is_archive = random_bool(self.misc_provider, is_archive)
            is_binary = random_bool(self.misc_provider, is_binary)
            is_media = random_bool(self.misc_provider, is_media)
            is_script = random_bool(self.misc_provider, is_script)
            is_source = random_bool(self.misc_provider, is_source)
            is_text = random_bool(self.misc_provider, is_text)
            mime_type = (
                mime_type if mime_type is not None else self.misc_provider.md5(False)
            )
            if percentage_of_license_text is None:
                percentage_of_license_text = self.random_int(max=10**5) / 10**5
            if programming_language is None:
                programming_language = entry_or_none(
                    self.misc_provider,
                    self.random_element(["Java", "Typescript", "HTML", "Python"]),
                )
        if options.package:
            if for_packages is None:
                for_packages = entry_or_none(
                    self.misc_provider, random_list(self, self.random_purl)
                )
            if package_data is None:
                package_data = random_list(self, self.package_data)
        if options.url and urls is None:
            urls = random_list(self, self.sc_url)
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
            md5=md5 if md5 is not None else self.misc_provider.md5(False),
            mime_type=mime_type,
            name=name or PurePath(path).name,
            package_data=package_data or [],
            path=path,
            percentage_of_license_text=percentage_of_license_text,
            programming_language=programming_language,
            scan_errors=scan_errors or [],
            sha1=sha1 if sha1 is not None else self.misc_provider.sha1(False),
            sha256=sha256 if sha256 is not None else self.misc_provider.sha256(False),
            size=size if size is not None else self.random_int(max=10**9),
            size_count=size_count,
            type=FileTypeModel.FILE,
            urls=urls,
        )

    def _convert_to_scancode_path(
        self, path_in_tree: str, options: OptionsModel
    ) -> str:
        if not options.input:
            return path_in_tree
        common_ancestor = PurePath(os.path.commonpath(options.input))
        full_path = PurePath(options.input[0]) / path_in_tree
        if not options.strip_root and not options.full_root:
            path = (full_path).relative_to(common_ancestor.parent)
        if options.strip_root and not options.full_root:
            path = (full_path).relative_to(common_ancestor)
        if options.full_root and not options.strip_root:
            # in the scancode file: no path starts with / even when --full-root is set
            if full_path.is_absolute():
                full_path = PurePath(*full_path.parts[1:])
            path = full_path
        return str(path)

    def random_purl(self) -> str:
        return str(
            PackageURL(
                type=self.lorem_provider.word(),
                subpath=self.internet_provider.uri_path(),
                version=self.bothify("##.##.##"),
                namespace=self.internet_provider.domain_name(),
                name=self.internet_provider.domain_name(),
            ).to_string()
        )

    def package_data(
        self,
        type: str | None = None,
        namespace: str | None = None,
        name: str | None = None,
        version: str | None = None,
        qualifiers: Any = None,
        subpath: str | None = None,
        primary_language: str | None = None,
        description: str | None = None,
        release_date: str | None = None,
        parties: list | None = None,
        keywords: list | None = None,
        homepage_url: str | None = None,
        download_url: str | None = None,
        size: int | None = None,
        sha1: str | None = None,
        md5: str | None = None,
        sha256: str | None = None,
        sha512: str | None = None,
        bug_tracking_url: str | None = None,
        code_view_url: str | None = None,
        vcs_url: str | None = None,
        copyright: str | None = None,
        holder: str | None = None,
        declared_license_expression: str | None = None,
        declared_license_expression_spdx: str | None = None,
        license_detections: list[FileBasedLicenseDetectionModel] | None = None,
        other_license_expression: str | None = None,
        other_license_expression_spdx: str | None = None,
        other_license_detections: list | None = None,
        extracted_license_statement: str | None = None,
        notice_text: str | None = None,
        source_packages: list | None = None,
        file_references: list | None = None,
        is_private: bool = False,
        is_virtual: bool = False,
        extra_data: dict[str, Any] | None = None,
        dependencies: list[DependencyModel] | None = None,
        repository_homepage_url: str | None = None,
        repository_download_url: str | None = None,
        api_data_url: str | None = None,
        datasource_id: str | None = None,
        purl: str | None = None,
    ) -> PackageDataModel:
        if purl is None:
            purl = self.random_purl()
        try:
            package_data = PackageURL.from_string(purl)
        except ValueError:
            package_data = PackageURL.from_string(self.random_purl())
        if name is None:
            name = package_data.name
        if namespace is None:
            namespace = package_data.namespace
        if type is None:
            type = package_data.type
        if version is None:
            version = package_data.version
        if qualifiers is None:
            qualifiers = package_data.qualifiers
        if subpath is None:
            subpath = package_data.subpath
        return PackageDataModel(
            type=type,
            namespace=namespace,
            name=name,
            version=version,
            qualifiers=qualifiers,
            subpath=subpath,
            primary_language=primary_language or self.language_code(),
            description=description or self.lorem_provider.paragraph(),
            release_date=release_date or self.date_provider.iso8601(),
            parties=parties or [],
            keywords=keywords or [],
            homepage_url=homepage_url
            or entry_or_none(self.misc_provider, self.internet_provider.url()),
            download_url=download_url
            or entry_or_none(self.misc_provider, self.internet_provider.url()),
            size=size or self.random_int(),
            sha1=sha1 or self.misc_provider.sha1(False),
            md5=md5 or self.misc_provider.md5(False),
            sha256=sha256 or self.misc_provider.sha256(False),
            sha512=sha512 or None,
            bug_tracking_url=bug_tracking_url
            or entry_or_none(self.misc_provider, self.internet_provider.url()),
            code_view_url=code_view_url
            or entry_or_none(self.misc_provider, self.internet_provider.url()),
            vcs_url=vcs_url
            or entry_or_none(self.misc_provider, self.internet_provider.url()),
            copyright=copyright or self.internet_provider.company_email(),
            holder=holder or self.internet_provider.company_email(),
            declared_license_expression=declared_license_expression
            or declared_license_expression,
            declared_license_expression_spdx=declared_license_expression_spdx
            or declared_license_expression_spdx,
            license_detections=license_detections or license_detections,
            other_license_expression=other_license_expression
            or other_license_expression,
            other_license_expression_spdx=other_license_expression_spdx
            or other_license_expression_spdx,
            other_license_detections=other_license_detections
            or other_license_detections,
            extracted_license_statement=extracted_license_statement
            or extracted_license_statement,
            notice_text=notice_text or self.lorem_provider.paragraph(),
            source_packages=source_packages or [],
            file_references=file_references or [],
            is_private=random_bool(self.misc_provider, is_private),
            is_virtual=random_bool(self.misc_provider, is_virtual),
            extra_data=extra_data or None,
            dependencies=dependencies
            or random_list(self, self.dependency, min_number_of_entries=0),
            repository_homepage_url=repository_homepage_url
            or entry_or_none(self.misc_provider, self.internet_provider.url()),
            repository_download_url=repository_download_url
            or entry_or_none(self.misc_provider, self.internet_provider.url()),
            api_data_url=api_data_url
            or entry_or_none(self.misc_provider, self.internet_provider.url()),
            datasource_id=datasource_id or "_".join(self.lorem_provider.words()),
            purl=purl or purl,
        )

    def dependency(
        self,
        purl: str | None = None,
        extracted_requirement: str | None = None,
        scope: str | None = None,
        is_runtime: bool = False,
        is_optional: bool = False,
        is_pinned: bool = False,
        is_direct: bool = False,
        resolved_package: Any = None,
        extra_data: Any = None,
    ) -> DependencyModel:
        return DependencyModel(
            purl=purl or self.random_purl(),
            extracted_requirement=extracted_requirement
            or "|".join(self.lorem_provider.words()),
            scope=scope or self.lorem_provider.word(),
            is_runtime=random_bool(self.misc_provider, is_runtime),
            is_optional=random_bool(self.misc_provider, is_optional),
            is_pinned=random_bool(self.misc_provider, is_pinned),
            is_direct=random_bool(self.misc_provider, is_direct),
            resolved_package=resolved_package,
            extra_data=extra_data,
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

    def sc_email(
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

    def sc_url(
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
