use super::RegistrySpec;
use xos_winupdate::hard_disable;

fn add(list: &mut Vec<RegistrySpec>, path: &str, build: i32, names: &[&str]) {
    for name in names {
        list.push(RegistrySpec {
            path: path.to_string(),
            name: name.to_string(),
            minimum_build: build,
            required_service: String::new(),
        });
    }
}

fn add_service(list: &mut Vec<RegistrySpec>, service: &str, path: &str, names: &[&str]) {
    for name in names {
        list.push(RegistrySpec {
            path: path.to_string(),
            name: name.to_string(),
            minimum_build: 0,
            required_service: service.to_string(),
        });
    }
}

pub(super) fn build_registry_specs() -> Vec<RegistrySpec> {
    let mut list: Vec<RegistrySpec> = Vec::new();
    add(
        &mut list,
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
        0,
        &[
            "DoNotConnectToWindowsUpdateInternetLocations",
            "DisableWindowsUpdateAccess",
            "ExcludeWUDriversInQualityUpdate",
            "SetUpdateNotificationLevel",
            "UpdateNotificationLevel",
            "SetAllowOptionalContent",
            "DeferFeatureUpdates",
            "DeferFeatureUpdatesPeriodInDays",
            "AllowAutoWindowsUpdateDownloadOverMeteredNetwork",
            "AllowOptionalContent",
            "DeferQualityUpdates",
            "DeferQualityUpdatesPeriodInDays",
            "PauseFeatureUpdatesStartTime",
            "PauseQualityUpdatesStartTime",
            "DisableDualScan",
            "SetDisableUXWUAccess",
            "WUServer",
            "WUStatusServer",
            "UpdateServiceUrlAlternate",
        ],
    );
    add(&mut list, hard_disable::OWNERSHIP_KEY, 0, &["Applied"]);
    add(
        &mut list,
        hard_disable::POLICY,
        19041,
        &hard_disable::CLASS_VALUES,
    );
    add(
        &mut list,
        hard_disable::AU,
        19041,
        &["UseUpdateClassPolicySource"],
    );
    add(
        &mut list,
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
        22000,
        &[
            "TargetReleaseVersion",
            "TargetReleaseVersionInfo",
            "ProductVersion",
        ],
    );
    add(
        &mut list,
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
        0,
        &[
            "NoAutoUpdate",
            "AUOptions",
            "UseWUServer",
            "NoAUShutdownOption",
            "AlwaysAutoRebootAtScheduledTime",
            "AutoInstallMinorUpdates",
            "NoAutoRebootWithLoggedOnUsers",
            "AllowMUUpdateService",
        ],
    );
    add(
        &mut list,
        r"HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
        0,
        &[
            "DisableWindowsUpdateAccess",
            "DoNotConnectToWindowsUpdateInternetLocations",
            "ExcludeWUDriversInQualityUpdate",
            "SetUpdateNotificationLevel",
            "UpdateNotificationLevel",
        ],
    );
    add(
        &mut list,
        r"HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
        0,
        &[
            "NoAutoUpdate",
            "AUOptions",
            "UseWUServer",
            "NoAUShutdownOption",
            "NoAutoRebootWithLoggedOnUsers",
        ],
    );
    add(
        &mut list,
        r"HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings",
        0,
        &[
            "IsContinuousInnovationOptedIn",
            "AllowMUUpdateService",
            "IsExpedited",
            "RestartNotificationsAllowed2",
            "ExcludeWUDriversInQualityUpdate",
            "BranchReadinessLevel",
            "DeferFeatureUpdates",
            "DeferFeatureUpdatesPeriodInDays",
            "DeferQualityUpdates",
            "DeferQualityUpdatesPeriodInDays",
            "AllowAutoWindowsUpdateDownloadOverMeteredNetwork",
            "PauseFeatureUpdatesStartTime",
            "PauseFeatureUpdatesEndTime",
            "PauseQualityUpdatesStartTime",
            "PauseQualityUpdatesEndTime",
            "PauseUpdatesStartTime",
            "PauseUpdatesExpiryTime",
            "PausedQualityDate",
            "PausedFeatureDate",
            "FlightSettingsMaxPauseDays",
            "PausedFeatureStatus",
            "PausedQualityStatus",
        ],
    );
    add(
        &mut list,
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverSearching",
        0,
        &[
            "SearchOrderConfig",
            "DontSearchWindowsUpdate",
            "DontPromptForWindowsUpdate",
            "DriverUpdateWizardWuSearchEnabled",
        ],
    );
    add(
        &mut list,
        r"HKCU\SOFTWARE\Policies\Microsoft\Windows\DriverSearching",
        0,
        &[
            "DontSearchWindowsUpdate",
            "DriverUpdateWizardWuSearchEnabled",
            "DontPromptForWindowsUpdate",
        ],
    );
    add(
        &mut list,
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching",
        0,
        &[
            "SearchOrderConfig",
            "DontSearchWindowsUpdate",
            "DontPromptForWindowsUpdate",
            "DriverUpdateWizardWuSearchEnabled",
        ],
    );
    add(
        &mut list,
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata",
        0,
        &["PreventDeviceMetadataFromNetwork"],
    );
    add(
        &mut list,
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata",
        0,
        &["PreventDeviceMetadataFromNetwork"],
    );
    add(
        &mut list,
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization",
        0,
        &["DODownloadMode"],
    );
    add(
        &mut list,
        r"HKCU\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization",
        0,
        &["DODownloadMode"],
    );
    add(
        &mut list,
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config",
        0,
        &["DODownloadMode"],
    );
    add(
        &mut list,
        r"HKLM\SOFTWARE\Policies\Microsoft\WindowsStore",
        0,
        &["AutoDownload"],
    );
    add(
        &mut list,
        r"HKCU\SOFTWARE\Policies\Microsoft\WindowsStore",
        0,
        &["AutoDownload"],
    );
    add(
        &mut list,
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate",
        0,
        &["AutoDownload"],
    );
    add(
        &mut list,
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        0,
        &["SettingsPageVisibility"],
    );
    add(
        &mut list,
        r"HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate",
        0,
        &[
            "Install{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}",
            "Update{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}",
            "Install{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}",
            "Update{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}",
            "Install{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}",
            "Update{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}",
            "Install{65C35B14-6C1D-4122-AC46-7148CC9D6497}",
            "Update{65C35B14-6C1D-4122-AC46-7148CC9D6497}",
            "Install{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
            "Update{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
            "Uninstall{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
        ],
    );

    add(
        &mut list,
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System",
        0,
        &[
            "EnableLUA",
            "ConsentPromptBehaviorAdmin",
            "PromptOnSecureDesktop",
        ],
    );
    add(
        &mut list,
        r"HKLM\Software\Policies\Microsoft\Windows\DeviceGuard",
        0,
        &[
            "EnableVirtualizationBasedSecurity",
            "RequirePlatformSecurityFeatures",
            "HypervisorEnforcedCodeIntegrity",
            "ConfigureSystemGuardLaunch",
            "LsaCfgFlags",
        ],
    );
    add(
        &mut list,
        r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard",
        0,
        &[
            "EnableVirtualizationBasedSecurity",
            "RequirePlatformSecurityFeatures",
            "Locked",
            "Mandatory",
        ],
    );
    add(
        &mut list,
        r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
        0,
        &["Enabled", "WasEnabledBy", "ChangedInBootCycle", "Locked"],
    );
    add(
        &mut list,
        r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard",
        0,
        &["Enabled", "WasEnabledBy", "ChangedInBootCycle", "Locked"],
    );
    add(
        &mut list,
        r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard",
        0,
        &["Enabled", "Locked"],
    );
    add(
        &mut list,
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        0,
        &["LsaCfgFlags"],
    );
    add(
        &mut list,
        r"HKLM\SYSTEM\CurrentControlSet\Control",
        0,
        &["SvcHostSplitThresholdInKB"],
    );
    add(
        &mut list,
        r"HKLM\SYSTEM\CurrentControlSet\Control\Power",
        0,
        &["HibernateEnabled", "HiberFileType"],
    );
    add(
        &mut list,
        r"HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\0012ee47-9041-4b5d-9b77-535fba8b1442\0b2d69d7-a2a1-449c-9680-f91c70521c60",
        0,
        &["Attributes"],
    );
    add(
        &mut list,
        r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power",
        0,
        &["HiberbootEnabled", "SleepStudyDisabled"],
    );
    add(
        &mut list,
        r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
        0,
        &["FeatureSettingsOverride", "FeatureSettingsOverrideMask"],
    );
    add(
        &mut list,
        r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
        0,
        &["fDenyTSConnections"],
    );
    add(
        &mut list,
        r"HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell",
        0,
        &["ExecutionPolicy"],
    );
    add(
        &mut list,
        r"HKLM\Software\Policies\Microsoft\Windows\System",
        0,
        &["ShowHibernateOption", "AllowClipboardHistory"],
    );

    add(
        &mut list,
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
        0,
        &[
            "ServiceKeepAlive",
            "PreviousRunningMode",
            "IsServiceRunning",
            "DisableAntiSpyware",
            "DisableAntiVirus",
            "PassiveMode",
            "DisableRealtimeMonitoring",
        ],
    );
    add(
        &mut list,
        r"HKLM\SOFTWARE\Microsoft\Windows Defender",
        0,
        &[
            "ServiceKeepAlive",
            "PreviousRunningMode",
            "IsServiceRunning",
            "DisableAntiSpyware",
            "DisableAntiVirus",
            "PassiveMode",
        ],
    );
    add(
        &mut list,
        r"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
        0,
        &[
            "DisableRealtimeMonitoring",
            "DisableBehaviorMonitoring",
            "DisableIOAVProtection",
            "DisableOnAccessProtection",
            "DisableScanOnRealtimeEnable",
        ],
    );
    add(
        &mut list,
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        0,
        &[
            "DisableRealtimeMonitoring",
            "DisableBehaviorMonitoring",
            "DisableIOAVProtection",
            "DisableOnAccessProtection",
            "DisableScanOnRealtimeEnable",
        ],
    );
    add(
        &mut list,
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager",
        0,
        &["AllowRealtimeMonitoring"],
    );
    add(
        &mut list,
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        0,
        &["SecurityHealth", "WindowsDefender"],
    );
    add(
        &mut list,
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
        0,
        &["SecurityHealth"],
    );
    add(
        &mut list,
        r"HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting",
        0,
        &["Disabled", "Disabled_Old"],
    );
    add(
        &mut list,
        r"HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy",
        0,
        &["VerifiedAndReputablePolicyState"],
    );
    add(
        &mut list,
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
        0,
        &["SmartScreenEnabled"],
    );
    add(
        &mut list,
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost",
        0,
        &["EnableWebContentEvaluation", "PreventOverride"],
    );
    add(
        &mut list,
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance",
        0,
        &["Enabled"],
    );

    add(
        &mut list,
        r"HKLM\Software\Policies\Microsoft\Windows\GameDVR",
        0,
        &["AllowGameDVR"],
    );
    add(
        &mut list,
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR",
        0,
        &[
            "AppCaptureEnabled",
            "AudioCaptureEnabled",
            "CursorCaptureEnabled",
            "HistoricalCaptureEnabled",
            "GameDVR_Enabled",
        ],
    );
    add(
        &mut list,
        r"HKCU\System\GameConfigStore",
        0,
        &[
            "GameDVR_Enabled",
            "GameDVR_DSEBehavior",
            "GameDVR_FSEBehaviorMode",
            "GameDVR_HonorUserFSEBehaviorMode",
            "GameDVR_DXGIHonorFSEWindowsCompatible",
            "GameDVR_EFSEFeatureFlags",
            "GameDVR_FSEBehavior",
            "GameDVR_HSEBehavior",
        ],
    );
    add(
        &mut list,
        r"HKCU\Software\Microsoft\GameBar",
        0,
        &[
            "AutoGameModeEnabled",
            "AllowAutoGameMode",
            "ShowStartupPanel",
            "UseNexusForGameBarEnabled",
        ],
    );
    add(
        &mut list,
        r"HKLM\System\CurrentControlSet\Control\GraphicsDrivers",
        0,
        &[
            "HwSchMode",
            "TdrDelay",
            "TdrDdiDelay",
            "DisableOverlays",
            "MiracastForceDisable",
        ],
    );
    add(
        &mut list,
        r"HKLM\Software\Microsoft\Windows\Dwm",
        0,
        &["OverlayTestMode", "OverlayMinFPS"],
    );
    add(
        &mut list,
        r"HKCU\Software\Microsoft\DirectX\UserGpuPreferences",
        0,
        &["DirectXUserGlobalSettings"],
    );
    add(
        &mut list,
        r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
        0,
        &["SystemResponsiveness", "NetworkThrottlingIndex"],
    );
    add(
        &mut list,
        r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
        0,
        &["GPU Priority", "Priority", "Scheduling Category"],
    );
    for executable in [
        "GameBarPresenceWriter.exe",
        "bcastdvr.exe",
        "GamePanel.exe",
        "GameBar.exe",
        "GameBarFTServer.exe",
        "GameBarFT.exe",
        "XboxGameBarWidgets.exe",
    ] {
        add(
            &mut list,
            &format!(
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{}",
                executable
            ),
            0,
            &["Debugger"],
        );
    }

    add(
        &mut list,
        r"HKCU\Software\Microsoft\Windows\DWM",
        0,
        &[
            "EnableAeroPeek",
            "AlwaysHibernateThumbnails",
            "ColorPrevalence",
            "CompositionPolicy",
        ],
    );
    add(
        &mut list,
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        0,
        &[
            "TaskbarAnimations",
            "ListviewAlphaSelect",
            "ListviewShadow",
            "ShowTaskViewButton",
            "ShowSecondsInSystemClock",
            "HideFileExt",
            "Hidden",
            "ShowSuperHidden",
            "TaskbarAl",
            "DisablePreviewDesktop",
        ],
    );
    add(
        &mut list,
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
        0,
        &["EnableAutoTray", "AltTabSettings", "HoverSelectDesktops"],
    );
    add(
        &mut list,
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
        0,
        &["HubMode"],
    );
    add(
        &mut list,
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3",
        0,
        &["1806"],
    );
    add(
        &mut list,
        r"HKCU\Software\Microsoft\Clipboard",
        0,
        &["EnableClipboardHistory"],
    );
    add(
        &mut list,
        r"HKCU\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}",
        22621,
        &["System.IsPinnedToNameSpaceTree"],
    );
    add(
        &mut list,
        r"HKCU\Software\Classes\CLSID\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}",
        22621,
        &["System.IsPinnedToNameSpaceTree"],
    );
    add(
        &mut list,
        r"HKCU\Software\Classes\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}",
        0,
        &["System.IsPinnedToNameSpaceTree"],
    );
    add(
        &mut list,
        r"HKCU\Control Panel\Mouse",
        0,
        &[
            "MouseHoverTime",
            "MouseSpeed",
            "MouseThreshold1",
            "MouseThreshold2",
            "RawMouseThrottleEnabled",
            "RawMouseThrottleDuration",
        ],
    );
    add(
        &mut list,
        r"HKCU\Control Panel\Keyboard",
        0,
        &[
            "KeyboardDelay",
            "KeyboardSpeed",
            "PrintScreenKeyForSnippingEnabled",
        ],
    );
    add(
        &mut list,
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications",
        0,
        &["GlobalUserDisabled", "GlobalUserOverride"],
    );
    add(
        &mut list,
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy",
        0,
        &[
            "LetAppsRunInBackground",
            "LetAppsRunInBackground_UserInControlOfTheseApps",
            "LetAppsRunInBackground_ForceAllowTheseApps",
            "LetAppsRunInBackground_ForceDenyTheseApps",
            "LetAppsAccessCamera",
            "LetAppsAccessMicrophone",
            "LetAppsAccessLocation",
        ],
    );
    add(
        &mut list,
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications",
        0,
        &["ToastEnabled"],
    );
    add(
        &mut list,
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search",
        0,
        &[
            "SearchboxTaskbarMode",
            "BingSearchEnabled",
            "CortanaConsent",
        ],
    );
    add(
        &mut list,
        r"HKLM\SOFTWARE\Microsoft\Windows Search",
        0,
        &["EnableIndexingBackoff", "SetupCompletedSuccessfully"],
    );
    add(
        &mut list,
        r"HKLM\SYSTEM\CurrentControlSet\Services\WSearch",
        0,
        &["DelayedAutoStart"],
    );
    for executable in ["SearchApp.exe", "SearchUI.exe", "SearchHost.exe"] {
        add(
            &mut list,
            &format!(
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{}",
                executable
            ),
            0,
            &["Debugger"],
        );
    }

    add(
        &mut list,
        r"HKCU\Software\OpenShell\StartMenu\Settings",
        0,
        &["MenuStyle", "SkinW7", "SkipMetro"],
    );
    add(
        &mut list,
        r"HKCU\Software\OpenShell\StartMenu",
        0,
        &["ShowedStyle2"],
    );

    add(
        &mut list,
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy",
        0,
        &["fMinimizeConnections", "fDisablePowerManagement"],
    );
    add(
        &mut list,
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\Local",
        0,
        &["fMinimizeConnections", "fDisablePowerManagement"],
    );
    add(
        &mut list,
        r"HKLM\System\CurrentControlSet\Services\Dnscache\Parameters",
        0,
        &[
            "EnableAutoDoh",
            "MaxCacheTtl",
            "MaxNegativeCacheTtl",
            "DisableCoalescing",
        ],
    );
    add(
        &mut list,
        r"HKLM\SYSTEM\CurrentControlSet\Services\USBHUB3\Parameters",
        0,
        &[
            "DisableOnSoftRemove",
            "EnhancedPowerManagementEnabled",
            "DeviceSelectiveSuspended",
            "SelectiveSuspendEnabled",
            "D3ColdSupported",
            "DisableLPM",
            "DisableSelectiveSuspendUI",
            "Ceip",
        ],
    );
    add(
        &mut list,
        r"HKLM\SYSTEM\CurrentControlSet\Services\usbccgp\Parameters",
        0,
        &["EnhancedPowerManagementEnabled", "D3ColdSupported"],
    );
    add(
        &mut list,
        r"HKLM\SYSTEM\CurrentControlSet\Services\pci\Parameters",
        0,
        &["ASPMOptOut", "D3ColdSupported"],
    );
    for service in [
        "BFE",
        "DcomLaunch",
        "mpssvc",
        "PlugPlay",
        "Power",
        "SamSs",
        "EventSystem",
        "CryptSvc",
        "Dhcp",
        "Dnscache",
        "DisplayEnhancementService",
        "PcaSvc",
        "WdiSystemHost",
        "AudioEndpointBuilder",
        "Appinfo",
        "BITS",
        "gpsvc",
        "IKEEXT",
        "iphlpsvc",
        "LanmanServer",
        "lmhosts",
        "NcbService",
        "RasAuto",
        "RasMan",
        "SENS",
        "ShellHWDetection",
        "SstpSvc",
        "TrkWks",
        "Winmgmt",
        "EventLog",
        "FontCache",
        "LanmanWorkstation",
        "NlaSvc",
        "nsi",
        "Schedule",
        "SessionEnv",
        "Themes",
        "W32Time",
        "Wcmsvc",
    ] {
        add_service(
            &mut list,
            service,
            &format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{}", service),
            &["SvcHostSplitDisable"],
        );
    }
    add(
        &mut list,
        r"HKLM\SOFTWARE\Microsoft\PolicyManager\default\Connectivity\DisableCrossDeviceResume",
        22631,
        &["value"],
    );
    add(
        &mut list,
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\CrossDeviceResume\Configuration",
        22631,
        &["IsResumeAllowed"],
    );
    add(
        &mut list,
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell\ShellUIHosts\CrossDeviceResumeHost",
        22631,
        &["ProcessPath"],
    );
    let mut seen = std::collections::HashSet::new();
    list.retain(|spec| seen.insert(format!("{}\0{}", spec.path, spec.name).to_uppercase()));
    list
}
