from csv import DictWriter
from typing import List

from prowler.lib.logger import logger
from prowler.lib.outputs.finding import Finding
from prowler.lib.outputs.output import Output
from prowler.lib.outputs.utils import unroll_dict, unroll_list


def sanitize_csv_value(value):
    if value is None:
        return ""
    if isinstance(value, (list, dict)):
        value = str(value)
    return (
        str(value)
        .replace("\r\n", " ")
        .replace("\n", " ")
        .replace("\r", " ")
        .replace("\t", " ")
        .strip()
    )


class CSV(Output):
    def transform(self, findings: List[Finding]) -> None:
        """Transforms the findings into the CSV format."""
        try:
            for finding in findings:
                finding_dict = {}

                finding_dict["AUTH_METHOD"] = sanitize_csv_value(finding.auth_method)
                finding_dict["TIMESTAMP"] = sanitize_csv_value(finding.timestamp)
                finding_dict["ACCOUNT_UID"] = sanitize_csv_value(finding.account_uid)
                finding_dict["ACCOUNT_NAME"] = sanitize_csv_value(finding.account_name)
                finding_dict["ACCOUNT_EMAIL"] = sanitize_csv_value(finding.account_email)
                finding_dict["ACCOUNT_ORGANIZATION_UID"] = sanitize_csv_value(
                    finding.account_organization_uid
                )
                finding_dict["ACCOUNT_ORGANIZATION_NAME"] = sanitize_csv_value(
                    finding.account_organization_name
                )
                finding_dict["ACCOUNT_TAGS"] = sanitize_csv_value(
                    unroll_dict(finding.account_tags, separator=":")
                )
                finding_dict["FINDING_UID"] = sanitize_csv_value(finding.uid)
                finding_dict["PROVIDER"] = sanitize_csv_value(finding.metadata.Provider)
                finding_dict["CHECK_ID"] = sanitize_csv_value(finding.metadata.CheckID)
                finding_dict["CHECK_TITLE"] = sanitize_csv_value(
                    finding.metadata.CheckTitle
                )
                finding_dict["CHECK_TYPE"] = sanitize_csv_value(
                    unroll_list(finding.metadata.CheckType)
                )
                finding_dict["STATUS"] = sanitize_csv_value(finding.status.value)
                finding_dict["STATUS_EXTENDED"] = sanitize_csv_value(
                    finding.status_extended
                )
                finding_dict["MUTED"] = sanitize_csv_value(finding.muted)
                finding_dict["SERVICE_NAME"] = sanitize_csv_value(
                    finding.metadata.ServiceName
                )
                finding_dict["SUBSERVICE_NAME"] = sanitize_csv_value(
                    finding.metadata.SubServiceName
                )
                finding_dict["SEVERITY"] = sanitize_csv_value(
                    finding.metadata.Severity.value
                )
                finding_dict["RESOURCE_TYPE"] = sanitize_csv_value(
                    finding.metadata.ResourceType
                )
                finding_dict["RESOURCE_UID"] = sanitize_csv_value(
                    finding.resource_uid
                )
                finding_dict["RESOURCE_NAME"] = sanitize_csv_value(
                    finding.resource_name
                )
                finding_dict["RESOURCE_DETAILS"] = sanitize_csv_value(
                    finding.resource_details
                )
                finding_dict["RESOURCE_TAGS"] = sanitize_csv_value(
                    unroll_dict(finding.resource_tags)
                )
                finding_dict["PARTITION"] = sanitize_csv_value(finding.partition)
                finding_dict["REGION"] = sanitize_csv_value(finding.region)
                finding_dict["DESCRIPTION"] = sanitize_csv_value(
                    finding.metadata.Description
                )
                finding_dict["RISK"] = sanitize_csv_value(finding.metadata.Risk)
                finding_dict["RELATED_URL"] = sanitize_csv_value(
                    finding.metadata.RelatedUrl
                )
                finding_dict["REMEDIATION_RECOMMENDATION_TEXT"] = sanitize_csv_value(
                    finding.metadata.Remediation.Recommendation.Text
                )
                finding_dict["REMEDIATION_RECOMMENDATION_URL"] = sanitize_csv_value(
                    finding.metadata.Remediation.Recommendation.Url
                )
                finding_dict["REMEDIATION_CODE_NATIVEIAC"] = sanitize_csv_value(
                    finding.metadata.Remediation.Code.NativeIaC
                )
                finding_dict["REMEDIATION_CODE_TERRAFORM"] = sanitize_csv_value(
                    finding.metadata.Remediation.Code.Terraform
                )
                finding_dict["REMEDIATION_CODE_CLI"] = sanitize_csv_value(
                    finding.metadata.Remediation.Code.CLI
                )
                finding_dict["REMEDIATION_CODE_OTHER"] = sanitize_csv_value(
                    finding.metadata.Remediation.Code.Other
                )
                finding_dict["COMPLIANCE"] = sanitize_csv_value(
                    unroll_dict(finding.compliance, separator=": ")
                )
                finding_dict["CATEGORIES"] = sanitize_csv_value(
                    unroll_list(finding.metadata.Categories)
                )
                finding_dict["DEPENDS_ON"] = sanitize_csv_value(
                    unroll_list(finding.metadata.DependsOn)
                )
                finding_dict["RELATED_TO"] = sanitize_csv_value(
                    unroll_list(finding.metadata.RelatedTo)
                )
                finding_dict["NOTES"] = sanitize_csv_value(
                    finding.metadata.Notes
                )
                finding_dict["PROWLER_VERSION"] = sanitize_csv_value(
                    finding.prowler_version
                )
                finding_dict["ADDITIONAL_URLS"] = sanitize_csv_value(
                    unroll_list(finding.metadata.AdditionalURLs)
                )

                self._data.append(finding_dict)

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def batch_write_data_to_file(self) -> None:
        """Writes the findings to a file using CSV format."""
        try:
            if (
                getattr(self, "_file_descriptor", None)
                and not self._file_descriptor.closed
                and self._data
            ):
                csv_writer = DictWriter(
                    self._file_descriptor,
                    fieldnames=self._data[0].keys(),
                    delimiter=";",
                )
                if self._file_descriptor.tell() == 0:
                    csv_writer.writeheader()
                for finding in self._data:
                    csv_writer.writerow(finding)
                if self.close_file or self._from_cli:
                    self._file_descriptor.close()
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
