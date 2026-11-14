pub const PRINT_FEATURES: &[&str] = &[
    "Printing-Foundation-Features",
    "Printing-Foundation-InternetPrinting-Client",
    "Printing-Foundation-LPDPrintService",
    "Printing-Foundation-LPRPortMonitor",
    "Printing-PrintToPDFServices-Features",
    "Printing-XPSServices-Features",
];

pub const PRINT_TASKS: &[&str] = &[
    r"\Microsoft\Windows\Printing\EduPrintProv",
    r"\Microsoft\Windows\Printing\PrinterCleanupTask",
    r"\Microsoft\Windows\Printing\PrintJobCleanupTask",
];

pub const HYPER_V_FEATURES: &[&str] = &[
    "Microsoft-Hyper-V-All",
    "Microsoft-Hyper-V",
    "Microsoft-Hyper-V-Tools-All",
    "Microsoft-Hyper-V-Management-PowerShell",
    "Microsoft-Hyper-V-Hypervisor",
    "Microsoft-Hyper-V-Services",
    "Microsoft-Hyper-V-Management-Clients",
    "HypervisorPlatform",
    "VirtualMachinePlatform",
];

pub const HYPER_V_DEVICES: &[&str] = &[r"ROOT\VID\0000", r"ROOT\VID\0001"];

pub const WIFI_TASKS: &[&str] = &[
    r"\Microsoft\Windows\WlanSvc\CDSSync",
    r"\Microsoft\Windows\WlanSvc\MoProfileManagement",
    r"\Microsoft\Windows\WCM\WiFiTask",
];

pub const BLUETOOTH_UNINSTALL_TASK: &str = r"\Microsoft\Windows\Bluetooth\UninstallDeviceTask";
