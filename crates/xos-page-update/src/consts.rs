pub const POL_WU: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";
pub const POL_WU_CU: &str = r"HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";
pub const POL_WU_AU: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";
pub const POL_WU_AU_CU: &str = r"HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";
pub const POL_DO: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization";
pub const POL_DO_CU: &str = r"HKCU\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization";
pub const DO_CONFIG: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config";
pub const DO_USER: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization";
pub const DO_NETWORK_SERVICE: &str =
    r"HKEY_USERS\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings";
pub const CURRENT_VERSION: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
pub const POL_STORE: &str = r"HKLM\SOFTWARE\Policies\Microsoft\WindowsStore";
pub const POL_STORE_CU: &str = r"HKCU\SOFTWARE\Policies\Microsoft\WindowsStore";
pub const STORE_SET: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate";
pub const UX_SET: &str = r"HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings";
pub const POL_DR: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverSearching";
pub const SYS_DR: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching";
pub const META: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata";
pub const META_POL: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata";
pub const POL_DR_CU: &str = r"HKCU\SOFTWARE\Policies\Microsoft\Windows\DriverSearching";
pub const POL_EXPL: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
pub const POL_MGR_UPDATE: &str = r"HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Update";
pub const UPDATE_SERVICE_BACKUP: &str = r"HKLM\SOFTWARE\XOSToolkit\UpdateServiceBackup";
pub const UPDATE_TASK_BACKUP: &str = r"HKLM\SOFTWARE\XOSToolkit\UpdateTaskBackup";
pub const UPDATE_VISIBILITY_BACKUP: &str = r"HKLM\SOFTWARE\XOSToolkit\UpdateVisibilityBackup";
pub const KGL_ONE: &str = r"HKLM\SOFTWARE\Microsoft\KGL\OneSettings";
pub const KGL_API: &str = "https://settings.data.microsoft.com/settings/v3.0/xbox/knowngamelist";

pub const UPDATE_SVCS: [&str; 6] = [
    "wuauserv",
    "bits",
    "dosvc",
    "UsoSvc",
    "WaaSMedicSvc",
    "uhssvc",
];
pub const UPDATE_SVCS_STOP_ORDER: [&str; 6] = [
    "uhssvc",
    "WaaSMedicSvc",
    "UsoSvc",
    "dosvc",
    "wuauserv",
    "bits",
];
pub const UPDATE_SVCS_START_ORDER: [&str; 2] = ["bits", "wuauserv"];

pub const BLOCKED_MODE_TASKS: [&str; 54] = [
    r"\Microsoft\Windows\WindowsUpdate\Scheduled Start",
    r"\Microsoft\Windows\UpdateOrchestrator\Schedule Scan",
    r"\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task",
    r"\Microsoft\Windows\WaaSMedic\PerformRemediation",
    r"\Microsoft\Windows\InstallService\RestoreDevice",
    r"\Microsoft\Windows\InstallService\ScanForUpdates",
    r"\Microsoft\Windows\InstallService\ScanForUpdatesAsUser",
    r"\Microsoft\Windows\InstallService\SmartRetry",
    r"\Microsoft\Windows\InstallService\WakeUpAndContinueUpdates",
    r"\Microsoft\Windows\InstallService\WakeUpAndScanForUpdates",
    r"\Microsoft\Windows\UpdateOrchestrator\Report policies",
    r"\Microsoft\Windows\UpdateOrchestrator\Schedule Maintenance Work",
    r"\Microsoft\Windows\UpdateOrchestrator\Schedule Wake To Work",
    r"\Microsoft\Windows\UpdateOrchestrator\Schedule Work",
    r"\Microsoft\Windows\UpdateOrchestrator\UIEOrchestrator",
    r"\Microsoft\Windows\UpdateOrchestrator\UpdateModelTask",
    r"\Microsoft\Windows\UpdateOrchestrator\Start Oobe Expedite Work",
    r"\Microsoft\Windows\UpdateOrchestrator\StartOobeAppsScan_OobeAppReady",
    r"\Microsoft\Windows\UpdateOrchestrator\StartOobeAppsScanAfterUpdate",
    r"\Microsoft\Windows\UpdateOrchestrator\UUS Failover Task",
    r"\Microsoft\Windows\UpdateOrchestrator\AC Power Download",
    r"\Microsoft\Windows\UpdateOrchestrator\AC Power Install",
    r"\Microsoft\Windows\UpdateOrchestrator\Backup Scan",
    r"\Microsoft\Windows\UpdateOrchestrator\Battery Saver Deferred Install",
    r"\Microsoft\Windows\UpdateOrchestrator\Driver Install",
    r"\Microsoft\Windows\UpdateOrchestrator\Maintenance Install",
    r"\Microsoft\Windows\UpdateOrchestrator\MusUx_LogonUpdateResults",
    r"\Microsoft\Windows\UpdateOrchestrator\MusUx_UpdateInterval",
    r"\Microsoft\Windows\UpdateOrchestrator\Policy Install",
    r"\Microsoft\Windows\UpdateOrchestrator\Reboot",
    r"\Microsoft\Windows\UpdateOrchestrator\Reboot_AC",
    r"\Microsoft\Windows\UpdateOrchestrator\Reboot_Battery",
    r"\Microsoft\Windows\UpdateOrchestrator\Refresh Settings",
    r"\Microsoft\Windows\UpdateOrchestrator\Resume On Boot",
    r"\Microsoft\Windows\UpdateOrchestrator\Schedule Retry Scan",
    r"\Microsoft\Windows\UpdateOrchestrator\StartOobeAppsScan",
    r"\Microsoft\Windows\UpdateOrchestrator\USO_Broker_Display",
    r"\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker_Display",
    r"\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker_ReadyToReboot",
    r"\Microsoft\Windows\UpdateOrchestrator\Universal Orchestrator Start",
    r"\Microsoft\Windows\UpdateOrchestrator\Universal Orchestrator Idle Start",
    r"\Microsoft\Windows\UpdateOrchestrator\UpdateAssistant",
    r"\Microsoft\Windows\UpdateOrchestrator\UpdateAssistantAllUsersRun",
    r"\Microsoft\Windows\UpdateOrchestrator\UpdateAssistantCalendarRun",
    r"\Microsoft\Windows\UpdateOrchestrator\UpdateAssistantWakeupRun",
    r"\Microsoft\Windows\WindowsUpdate\AUScheduledInstall",
    r"\Microsoft\Windows\WindowsUpdate\AUSessionConnect",
    r"\Microsoft\Windows\WindowsUpdate\Automatic App Update",
    r"\Microsoft\Windows\WindowsUpdate\RUXIM\PLUGScheduler",
    r"\Microsoft\Windows\WindowsUpdate\Scheduled Start With Network",
    r"\Microsoft\Windows\WindowsUpdate\sih",
    r"\Microsoft\Windows\WindowsUpdate\sihboot",
    r"\Microsoft\Windows\WindowsUpdate\sihpostreboot",
    r"\Microsoft\Windows\UpdateOrchestrator\StartOobeAppsScan_LicenseAccepted",
];

pub const UPDATE_TASK_PATHS: [&str; 4] = [
    r"\Microsoft\Windows\UpdateOrchestrator",
    r"\Microsoft\Windows\WaaSMedic",
    r"\Microsoft\Windows\WindowsUpdate",
    r"\Microsoft\Windows\InstallService",
];

pub const ORCHESTRATOR_MANAGED_TASKS: [&str; 3] = [
    r"\Microsoft\Windows\UpdateOrchestrator\Schedule Maintenance Work",
    r"\Microsoft\Windows\UpdateOrchestrator\Schedule Wake To Work",
    r"\Microsoft\Windows\UpdateOrchestrator\Schedule Work",
];

pub const HOME_HARD_DISABLE_NOTE: &str = "On Windows Home update policies are best effort. Hard Disabled also protects the disabled update services from ordinary repair; privileged Windows servicing can replace that protection.";
pub const HOME_POLICY_NOTE: &str = "On Windows Home this policy value is applied but may not take effect: Microsoft documents no update policy for Home, and Windows may still install updates automatically.";

pub const SERVICE_WAIT_POLL_MS: u64 = 250;
pub const SERVICE_START_WAIT_MS: u64 = 10000;
pub const SERVICE_STOP_WAIT_MS: u64 = 120000;

pub const MU_SERVICE_ID: &str = "7971f918-a847-4430-9279-4a52d1efe18d";
