"""Public result vocabulary paired with the installer; never exception text.

A regex is insufficient: an otherwise valid-looking token could be a credential.
Unknown values always become a fixed generic code, including in local logs.
"""

REASONS = frozenset('''
InstallerFailed InvalidOrUnavailableInstallerInput
ExplicitWorkspaceInferenceRequired GatewayBootstrapCommandFailed
GatewayClientIdentityMismatch GatewayConfigRequiresMigration GatewayIdentityMismatch
GatewayNotReady GatewayPKIMismatch GatewayPortInUse GatewayServiceTransitioning
GatewayStateAlreadyExists GatewayUnitMismatch InferenceNotConverged
InferenceProviderMustBeEnabled InputTooLarge InstallerVersionMismatch InvalidGatewayState
InvalidInstallerBOM InvalidInstallerRequest InvalidMachineIdentity InvalidOpenShellCollection
InvalidProviderCredential InvalidResolvedProfiles InvalidRevision InvalidWorkspaceMembers
OpenShellCollectionLimit OpenShellCommandFailed OpenShellOutputTooLarge OwnerAdminRequired
ProviderNotConverged ProviderTypeChangeRequiresMigration ProviderWorkspaceMismatch
RootlessCommandFailed RootlessEngineRequired RootlessGatewayRequired RootlessSocketUnavailable
RootlessSubordinateIDsRequired SandboxApplyNotImplemented SoftwareReleaseMismatch
SoftwareUpgradeNotImplemented UnexpectedGatewayClientConfig UnownedGatewayState
UnqualifiedGatewayUnit UnsafeGatewayIdentity UnsafeGatewayRuntimeState UnsafeGatewayState
UnsafeRootlessAccount UnsafeRootlessSocket UnsupportedProviderCredential UnsupportedWorkspaceName
WorkspaceMembersNotConverged WorkspaceNotActive WorkspaceNotConverged WorkspaceOwnershipConflict
'''.split())


def safe_reason(value):
    return value if isinstance(value, str) and value in REASONS else 'InstallerFailed'


class InstallerFailed(Exception):
    def __init__(self, reason=None, phase=None):
        self.reason = safe_reason(reason)
        self.phase = phase if phase in ('validate', 'apply', 'verify') else None
        super().__init__(self.reason)
