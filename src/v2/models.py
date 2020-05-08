"""Response model for both StackAggregator and Recommender."""
# generated by datamodel-codegen:
#   filename:  v2.yaml
#   timestamp: 2020-04-25T19:10:47+00:00

from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field, validator


class Ecosystem(str, Enum):  # noqa: D101  # noqa: D101
    maven = 'maven'
    pypi = 'pypi'
    npm = 'npm'


class Severity(str, Enum):  # noqa: D101  # noqa: D101
    low = 'low'
    medium = 'medium'
    high = 'high'
    critical = 'critical'


class BasicVulnerabilityFields(BaseModel):  # noqa: D101
    cve_ids: Optional[List[str]] = None
    cvss: float
    cwes: Optional[List[str]] = None
    cvss_v3: str
    severity: 'Severity'
    title: str
    id: str
    url: str


class Exploit(str, Enum):  # noqa: D101
    High = 'High'
    Functional = 'Functional'
    Proof_of_Concept = 'Proof of Concept'
    Unproven = 'Unproven'
    Not_Defined = 'Not Defined'


class Reference(BaseModel):  # noqa: D101
    title: Optional[str] = None
    url: Optional[str] = None


class PremiumVulnerabilityFields(BasicVulnerabilityFields):  # noqa: D101
    malicious: Optional[bool] = True
    patch_exists: Optional[bool] = False
    fixable: Optional[bool] = False
    exploit: Optional['Exploit'] = None
    description: Optional[str] = None
    fixed_in: Optional[List[str]] = None
    references: Optional[List['Reference']] = None


class Package(BaseModel):  # noqa: D101
    name: str
    version: str
    dependencies: Optional[List['Package']] = None

    def __eq__(self, other: "Package") -> bool:
        """Compare current instance with given one and returns True is same."""
        return other and self.name == other.name and self.version == other.version

    def __hash__(self) -> str:
        """Calculate hash value."""
        return hash((self.name, self.version))


class ComponentConflictLicensesItem(BaseModel):  # noqa: D101
    license1: Optional[str] = None
    license2: Optional[str] = None


class ComponentConflictItem(BaseModel):  # noqa: D101
    package: str
    conflict_licenses: List[ComponentConflictLicensesItem]


class UnknownItem(BaseModel):  # noqa: D101
    package: Optional[str] = None
    license: Optional[str] = None


class UnknownLicenses(BaseModel):  # noqa: D101
    component_conflict: Optional[List['ComponentConflictItem']] = None
    unknown: Optional[List['UnknownItem']] = None


class ConflictPackages(BaseModel):  # noqa: D101
    package1: str
    license1: str
    package2: str
    license2: str


class LicenseAnalysis(BaseModel):  # noqa: D101
    outlier_packages: List[Dict[str, Any]] = None
    conflict_packages: List['ConflictPackages'] = None
    current_stack_license: Dict[str, Any] = None
    unknown_licenses: 'UnknownLicenses' = None
    distinct_licenses: Optional[List[str]] = None
    stack_license_conflict: Optional[bool] = None
    total_licenses: Optional[int] = None


class UsedByItem(BaseModel):  # noqa: D101
    name: Optional[str] = None
    stars: Optional[int] = None


class GitHubDetails(BaseModel):  # noqa: D101
    watchers: Optional[int] = None
    first_release_date: Optional[str] = None
    total_releases: Optional[int] = None
    issues: Optional[Dict[str, Any]] = None
    pull_requests: Optional[Dict[str, Any]] = None
    dependent_repos: Optional[int] = None
    open_issues_count: Optional[int] = None
    latest_release_duration: Optional[str] = None
    forks_count: Optional[int] = None
    contributors: Optional[int] = None
    size: Optional[str] = None
    stargazers_count: Optional[int] = None
    used_by: Optional[List[UsedByItem]] = None
    dependent_projects: Optional[int] = None


class PackageDetails(Package):  # noqa: D101
    latest_version: str
    github: Optional['GitHubDetails'] = None
    licenses: Optional[List[str]] = None
    ecosystem: 'Ecosystem'
    url: Optional[str] = None


class PackageDetailsForRegisteredUser(PackageDetails):  # noqa: D101
    public_vulnerabilities: Optional[List['PremiumVulnerabilityFields']] = Field(
        None, description='Publicly known vulnerability details'
    )
    private_vulnerabilities: Optional[List['PremiumVulnerabilityFields']] = Field(
        None,
        description='Private vulnerability details, available only to registered\nusers\n',
    )
    recommended_version: Optional[str] = Field(
        None,
        description=('Recommended package version which includes '
                     'fix for both public and private vulnerabilities.\n'),
    )
    vulnerable_dependencies: Optional[List['PackageDetailsForRegisteredUser']] = Field(
        None, description='List of dependencies which are vulnerable.\n'
    )


class PackageDetailsForFreeTier(PackageDetails):  # noqa: D101
    public_vulnerabilities: Optional[List['BasicVulnerabilityFields']] = Field(
        None, description='Publicly known vulnerability details'
    )
    private_vulnerabilities: Optional[List['BasicVulnerabilityFields']] = Field(
        None, description='Private vulnerability details with limited info'
    )
    recommended_version: Optional[str] = Field(
        None,
        description='Recommended package version which includes fix for public vulnerabilities.\n',
    )
    vulnerable_dependencies: Optional[List['PackageDetailsForFreeTier']] = Field(
        None, description='List of dependencies which are vulnerable.\n'
    )


class RecommendedPackageData(PackageDetails):  # noqa: D101
    confidence_reason: Optional[float] = None
    reason: Optional[str] = None
    topic_list: Optional[List[str]] = None


class RegistrationStatus(str, Enum):  # noqa: D101
    registered = 'registered'
    freetier = 'freetier'


class RecommendationStatus(str, Enum):  # noqa: D101
    success = 'success'
    pgm_error = 'pgm_error'


class Audit(BaseModel):  # noqa: D101
    started_at: str
    ended_at: str
    version: str


class StackAggregatorResult(BaseModel):  # noqa: D101
    _audit: Optional['Audit'] = None
    uuid: Optional[UUID] = None
    external_request_id: Optional[str] = None
    registration_status: Optional['RegistrationStatus'] = None
    manifest_file_path: Optional[str] = None
    manifest_name: Optional[str] = None
    ecosystem: Optional['Ecosystem'] = None
    unknown_dependencies: Optional[List['Package']] = None
    license_analysis: Optional['LicenseAnalysis'] = None


class StackAggregatorResultForRegisteredUser(StackAggregatorResult):  # noqa: D101
    analyzed_dependencies: Optional[List['PackageDetailsForRegisteredUser']] = Field(
        None,
        description="All direct dependencies details regardless of it's vulnerability status\n",
    )


class StackAggregatorResultForFreeTier(StackAggregatorResult):  # noqa: D101
    registration_link: str
    analyzed_dependencies: Optional[List['PackageDetailsForFreeTier']] = Field(
        None,
        description="All direct dependencies details regardless of it's vulnerability status\n",
    )


class StackAggregatorRequest(BaseModel):  # noqa: D101
    registration_status: 'RegistrationStatus' = 'freetier'
    uuid: UUID = None
    external_request_id: str
    show_transitive: Optional[bool] = Field(
        True,
        description='This is required to enable or disable the transitive support\n',
    )
    ecosystem: 'Ecosystem'
    manifest_file: str
    manifest_file_path: str
    packages: List['Package']

    @validator('ecosystem', pre=True)
    def _normalize_ecosystem(ecosystem):
        return ecosystem.lower()


class StackRecommendationResult(BaseModel):  # noqa: D101
    _audit: 'Audit'
    uuid: UUID
    external_request_id: str
    registration_status: 'RegistrationStatus'
    recommendation_status: 'RecommendationStatus'
    companion: List['RecommendedPackageData']
    manifest_file_path: str
    usage_outliers: List[Dict[str, Any]]


class RecommenderRequest(StackAggregatorRequest):  # noqa: D101
    pass


Package.update_forward_refs()
PackageDetailsForRegisteredUser.update_forward_refs()
PackageDetailsForFreeTier.update_forward_refs()
