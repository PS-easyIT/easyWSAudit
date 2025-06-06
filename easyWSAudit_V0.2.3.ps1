# easyWSAudit - Windows Server Audit Tool
# Version: 0.0.3

# Debug-Modus - Auf $true setzen fuer ausfuehrliche Logging-Informationen
$DEBUG = $false
$DebugLogPath = "$env:TEMP\easyWSAudit_Debug.log"

# Debug-Funktion
function Write-DebugLog {
    param(
        [string]$Message,
        [string]$Source = "General"
    )
    
    if ($DEBUG) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
        $logMessage = "[$timestamp] [$Source] $Message"
        
        # Ausgabe in die Konsole
        Write-Host $logMessage -ForegroundColor Yellow
        
        # Ausgabe in die Log-Datei
        Add-Content -Path $DebugLogPath -Value $logMessage
        
        # Wenn das Debug-Display vorhanden ist, dort auch anzeigen
        if ($script:txtDebugOutput -and $window) {
            try {
                $script:txtDebugOutput.Dispatcher.Invoke([Action]{
                    $script:txtDebugOutput.Text += "$logMessage`r`n"
                    $script:txtDebugOutput.ScrollToEnd()
                }, "Normal")
            } catch {
                # Ignoriere Dispatcher-Fehler
            }
        }
    }
}

# Starte das Debug-Log
if ($DEBUG) {
    $startMessage = "=== easyWSAudit Debug Log gestartet $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") ==="
    Set-Content -Path $DebugLogPath -Value $startMessage -Force
    Write-Host $startMessage -ForegroundColor Cyan
}

# Importiere notwendige Module
Write-DebugLog "Importiere notwendige Module..." "Init"
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Windows.Forms # Fuer den SaveFileDialog
Write-DebugLog "Module importiert" "Init"

# Definiere die Commands fuer verschiedene Server-Rollen und Systeminformationen
$commands = @(
    # === SYSTEM INFORMATIONEN ===
    @{Name="Systeminformationen"; Command="Get-ComputerInfo"; Type="PowerShell"; Category="System"},
    @{Name="Betriebssystem Details"; Command="Get-CimInstance Win32_OperatingSystem"; Type="PowerShell"; Category="System"},
    @{Name="Hardware Informationen"; Command="Get-CimInstance Win32_ComputerSystem"; Type="PowerShell"; Category="Hardware"},
    @{Name="CPU Informationen"; Command="Get-CimInstance Win32_Processor"; Type="PowerShell"; Category="Hardware"},
    @{Name="Arbeitsspeicher Details"; Command="Get-CimInstance Win32_PhysicalMemory"; Type="PowerShell"; Category="Hardware"},
    @{Name="Festplatten Informationen"; Command="Get-CimInstance Win32_LogicalDisk"; Type="PowerShell"; Category="Storage"},
    @{Name="Volume Informationen"; Command="Get-Volume"; Type="PowerShell"; Category="Storage"},
    @{Name="Installierte Features und Rollen"; Command="Get-WindowsFeature | Where-Object { `$_.Installed -eq `$true }"; Type="PowerShell"; Category="Features"},
    @{Name="Installierte Programme"; Command="Get-CimInstance Win32_Product | Select-Object Name, Version, Vendor | Sort-Object Name"; Type="PowerShell"; Category="Software"},
    @{Name="Windows Updates"; Command="Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20"; Type="PowerShell"; Category="Updates"},
    @{Name="Netzwerkkonfiguration"; Command="Get-NetIPConfiguration"; Type="PowerShell"; Category="Network"},
    @{Name="Netzwerkadapter"; Command="Get-NetAdapter"; Type="PowerShell"; Category="Network"},
    @{Name="Aktive Netzwerkverbindungen"; Command="Get-NetTCPConnection | Where-Object State -eq 'Listen' | Select-Object LocalAddress, LocalPort, OwningProcess"; Type="PowerShell"; Category="Network"},
    @{Name="Firewall Regeln"; Command="Get-NetFirewallRule | Where-Object Enabled -eq 'True' | Select-Object DisplayName, Direction, Action | Sort-Object DisplayName"; Type="PowerShell"; Category="Security"},
    @{Name="Services (Automatisch)"; Command="Get-Service | Where-Object StartType -eq 'Automatic' | Sort-Object Status, Name"; Type="PowerShell"; Category="Services"},
    @{Name="Services (Laufend)"; Command="Get-Service | Where-Object Status -eq 'Running' | Sort-Object Name"; Type="PowerShell"; Category="Services"},
    @{Name="Geplante Aufgaben"; Command="Get-ScheduledTask | Where-Object State -eq 'Ready' | Select-Object TaskName, TaskPath, State"; Type="PowerShell"; Category="Tasks"},
    @{Name="Event-Log System (Letzte 24h)"; Command="Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 50 | Select-Object TimeCreated, Id, LevelDisplayName, Message"; Type="PowerShell"; Category="Events"},
    @{Name="Event-Log Application (Letzte 24h)"; Command="Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 50 | Select-Object TimeCreated, Id, LevelDisplayName, Message"; Type="PowerShell"; Category="Events"},
    @{Name="Lokale Benutzer"; Command="Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordRequired"; Type="PowerShell"; Category="Security"},
    @{Name="Lokale Gruppen"; Command="Get-LocalGroup | Select-Object Name, Description"; Type="PowerShell"; Category="Security"},
    
    # === ACTIVE DIRECTORY UMFASSENDE AUDITS ===
    @{Name="AD Domain Controller Status"; Command="Get-ADDomainController -Filter * | Select-Object Name, Site, IPv4Address, OperatingSystem, IsGlobalCatalog, IsReadOnly"; Type="PowerShell"; FeatureName="AD-Domain-Services"; Category="Active-Directory"},
    @{Name="AD Domain Informationen"; Command="Get-ADDomain | Select-Object Name, NetBIOSName, DomainMode, PDCEmulator, RIDMaster, InfrastructureMaster"; Type="PowerShell"; FeatureName="AD-Domain-Services"; Category="Active-Directory"},
    @{Name="AD Forest Informationen"; Command="Get-ADForest | Select-Object Name, ForestMode, DomainNamingMaster, SchemaMaster, Sites, Domains"; Type="PowerShell"; FeatureName="AD-Domain-Services"; Category="Active-Directory"},
    @{Name="AD Organizational Units"; Command="Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName, Description | Sort-Object Name"; Type="PowerShell"; FeatureName="AD-Domain-Services"; Category="Active-Directory"},
    @{Name="AD Domaenen Administratoren"; Command="Get-ADGroupMember -Identity 'Domain Admins' | Get-ADUser -Properties LastLogonDate, PasswordLastSet, Enabled | Select-Object Name, SamAccountName, Enabled, LastLogonDate, PasswordLastSet"; Type="PowerShell"; FeatureName="AD-Domain-Services"; Category="Active-Directory"},
    @{Name="AD Enterprise Administratoren"; Command="Get-ADGroupMember -Identity 'Enterprise Admins' | Get-ADUser -Properties LastLogonDate, PasswordLastSet, Enabled | Select-Object Name, SamAccountName, Enabled, LastLogonDate, PasswordLastSet"; Type="PowerShell"; FeatureName="AD-Domain-Services"; Category="Active-Directory"},
    @{Name="AD Schema Administratoren"; Command="Get-ADGroupMember -Identity 'Schema Admins' | Get-ADUser -Properties LastLogonDate, PasswordLastSet, Enabled | Select-Object Name, SamAccountName, Enabled, LastLogonDate, PasswordLastSet"; Type="PowerShell"; FeatureName="AD-Domain-Services"; Category="Active-Directory"},
    @{Name="AD Privilegierte Gruppen"; Command="@('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators','Print Operators','Server Operators') | ForEach-Object { Get-ADGroup -Identity `$_ -Properties Members | Select-Object Name, @{Name='MemberCount';Expression={`$_.Members.Count}} }"; Type="PowerShell"; FeatureName="AD-Domain-Services"; Category="Active-Directory"},
    @{Name="AD Benutzer ohne Passwort-Ablauf"; Command="Get-ADUser -Filter {PasswordNeverExpires -eq `$true -and Enabled -eq `$true} -Properties PasswordNeverExpires, LastLogonDate | Select-Object Name, SamAccountName, LastLogonDate"; Type="PowerShell"; FeatureName="AD-Domain-Services"; Category="Active-Directory"},
    @{Name="AD Deaktivierte Benutzer"; Command="Get-ADUser -Filter {Enabled -eq `$false} | Select-Object Name, SamAccountName, DistinguishedName | Sort-Object Name"; Type="PowerShell"; FeatureName="AD-Domain-Services"; Category="Active-Directory"},
    @{Name="AD Computer Accounts"; Command="Get-ADComputer -Filter * -Properties OperatingSystem, LastLogonDate | Select-Object Name, OperatingSystem, LastLogonDate, Enabled | Sort-Object LastLogonDate -Descending"; Type="PowerShell"; FeatureName="AD-Domain-Services"; Category="Active-Directory"},
    @{Name="AD Replikations-Status"; Command="repadmin /replsummary"; Type="CMD"; FeatureName="AD-Domain-Services"; Category="Active-Directory"},
    @{Name="AD FSMO Rollen"; Command="Get-ADDomain | Select-Object PDCEmulator, RIDMaster, InfrastructureMaster; Get-ADForest | Select-Object DomainNamingMaster, SchemaMaster"; Type="PowerShell"; FeatureName="AD-Domain-Services"; Category="Active-Directory"},
    @{Name="AD Sites und Subnets"; Command="Get-ADReplicationSite | Select-Object Name, Description; Get-ADReplicationSubnet -Filter * | Select-Object Name, Site, Location"; Type="PowerShell"; FeatureName="AD-Domain-Services"; Category="Active-Directory"},
    @{Name="AD Trust Relationships"; Command="Get-ADTrust -Filter * | Select-Object Name, Direction, TrustType, DisallowTransivity"; Type="PowerShell"; FeatureName="AD-Domain-Services"; Category="Active-Directory"},
    
    # === DNS UMFASSENDE DIAGNOSEN ===
    @{Name="DNS Server Konfiguration"; Command="Get-DnsServer | Select-Object ComputerName, ZoneScavenging, EnableDnsSec, ServerSetting"; Type="PowerShell"; FeatureName="DNS"; Category="DNS"},
    @{Name="DNS Server Zonen"; Command="Get-DnsServerZone | Select-Object ZoneName, ZoneType, IsAutoCreated, IsDsIntegrated, IsReverseLookupZone"; Type="PowerShell"; FeatureName="DNS"; Category="DNS"},
    @{Name="DNS Forwarders"; Command="Get-DnsServerForwarder"; Type="PowerShell"; FeatureName="DNS"; Category="DNS"},
    @{Name="DNS Cache-Inhalt"; Command="Get-DnsServerCache | Select-Object -First 20"; Type="PowerShell"; FeatureName="DNS"; Category="DNS"},
    @{Name="DNS Scavenging Einstellungen"; Command="Get-DnsServerScavenging"; Type="PowerShell"; FeatureName="DNS"; Category="DNS"},
    @{Name="DNS Event-Log Errors"; Command="Get-WinEvent -FilterHashtable @{LogName='DNS Server'; Level=2,3} -MaxEvents 50 | Select-Object TimeCreated, Id, LevelDisplayName, Message"; Type="PowerShell"; FeatureName="DNS"; Category="DNS"},
    @{Name="DNS Root Hints"; Command="Get-DnsServerRootHint"; Type="PowerShell"; FeatureName="DNS"; Category="DNS"},
    @{Name="DNS Service Dependencies"; Command="`$Services='DNS','Netlogon','Kerberos Key Distribution Center'; ForEach (`$Service in `$Services) {Get-Service `$Service | Select-Object Name, Status, StartType}"; Type="PowerShell"; FeatureName="DNS"; Category="DNS"},
    
    # === DHCP UMFASSENDE AUDITS ===
    @{Name="DHCP Server Konfiguration"; Command="Get-DhcpServerInDC"; Type="PowerShell"; FeatureName="DHCP"; Category="DHCP"},
    @{Name="DHCP Server Settings"; Command="Get-DhcpServerSetting"; Type="PowerShell"; FeatureName="DHCP"; Category="DHCP"},
    @{Name="DHCP IPv4 Bereiche"; Command="Get-DhcpServerv4Scope | Select-Object ScopeId, Name, StartRange, EndRange, SubnetMask, State, LeaseDuration"; Type="PowerShell"; FeatureName="DHCP"; Category="DHCP"},
    @{Name="DHCP IPv6 Bereiche"; Command="Get-DhcpServerv6Scope | Select-Object Prefix, Name, State, PreferredLifetime"; Type="PowerShell"; FeatureName="DHCP"; Category="DHCP"},
    @{Name="DHCP Reservierungen"; Command="Get-DhcpServerv4Reservation | Select-Object ScopeId, IPAddress, ClientId, Name, Description"; Type="PowerShell"; FeatureName="DHCP"; Category="DHCP"},
    @{Name="DHCP Lease-Statistiken"; Command="Get-DhcpServerv4ScopeStatistics | Select-Object ScopeId, AddressesFree, AddressesInUse, PercentageInUse"; Type="PowerShell"; FeatureName="DHCP"; Category="DHCP"},
    @{Name="DHCP Optionen (Server)"; Command="Get-DhcpServerv4OptionValue | Select-Object OptionId, Name, Value"; Type="PowerShell"; FeatureName="DHCP"; Category="DHCP"},
    @{Name="DHCP Failover Konfiguration"; Command="Get-DhcpServerv4Failover | Select-Object Name, PartnerServer, Mode, State"; Type="PowerShell"; FeatureName="DHCP"; Category="DHCP"},
    @{Name="DHCP Event-Log"; Command="Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Dhcp-Server/Operational'} -MaxEvents 50 | Select-Object TimeCreated, Id, LevelDisplayName, Message"; Type="PowerShell"; FeatureName="DHCP"; Category="DHCP"},
    
    # === IIS UMFASSENDE AUDITS ===
    @{Name="IIS Server Informationen"; Command="Get-IISServerManager | Select-Object *"; Type="PowerShell"; FeatureName="Web-Server"; Category="IIS"},
    @{Name="IIS Websites"; Command="Get-IISSite | Select-Object Name, Id, State, PhysicalPath, @{Name='Bindings';Expression={`$_.Bindings | ForEach-Object {`$_.Protocol + '://' + `$_.BindingInformation}}}"; Type="PowerShell"; FeatureName="Web-Server"; Category="IIS"},
    @{Name="IIS Application Pools"; Command="Get-IISAppPool | Select-Object Name, State, ProcessModel, Recycling"; Type="PowerShell"; FeatureName="Web-Server"; Category="IIS"},
    @{Name="IIS Anwendungen"; Command="Get-WebApplication | Select-Object Site, Path, PhysicalPath, ApplicationPool"; Type="PowerShell"; FeatureName="Web-Server"; Category="IIS"},
    @{Name="IIS Virtuelle Verzeichnisse"; Command="Get-WebVirtualDirectory | Select-Object Site, Application, Path, PhysicalPath"; Type="PowerShell"; FeatureName="Web-Server"; Category="IIS"},
    @{Name="IIS SSL Zertifikate"; Command="Get-ChildItem IIS:SslBindings | Select-Object IPAddress, Port, Host, Thumbprint, Subject"; Type="PowerShell"; FeatureName="Web-Server"; Category="IIS"},
    @{Name="IIS Modules"; Command="Get-WebGlobalModule | Select-Object Name, Image"; Type="PowerShell"; FeatureName="Web-Server"; Category="IIS"},
    @{Name="IIS Handler Mappings"; Command="Get-WebHandler | Select-Object Name, Path, Verb, Modules"; Type="PowerShell"; FeatureName="Web-Server"; Category="IIS"},
    @{Name="IIS Event-Log"; Command="Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-IIS*'} -MaxEvents 50 | Select-Object TimeCreated, Id, LevelDisplayName, Message"; Type="PowerShell"; FeatureName="Web-Server"; Category="IIS"},
    
    # === WDS (WINDOWS DEPLOYMENT SERVICES) ===
    @{Name="WDS Server Konfiguration"; Command="wdsutil /get-server /show:config"; Type="CMD"; FeatureName="WDS"; Category="WDS"},
    @{Name="WDS Boot Images"; Command="wdsutil /get-allimages /show:install"; Type="CMD"; FeatureName="WDS"; Category="WDS"},
    @{Name="WDS Install Images"; Command="wdsutil /get-allimages /show:boot"; Type="CMD"; FeatureName="WDS"; Category="WDS"},
    @{Name="WDS Transport Server"; Command="wdsutil /get-transportserver /show:config"; Type="CMD"; FeatureName="WDS"; Category="WDS"},
    @{Name="WDS Multicast"; Command="wdsutil /get-allmulticasttransmissions"; Type="CMD"; FeatureName="WDS"; Category="WDS"},
    @{Name="WDS Client Einstellungen"; Command="Get-WdsClient | Select-Object DeviceID, DeviceName, BootImagePath, ReferralServer"; Type="PowerShell"; FeatureName="WDS"; Category="WDS"},
    
    # === HYPER-V AUDITS ===
    @{Name="Hyper-V Host Informationen"; Command="Get-VMHost | Select-Object ComputerName, LogicalProcessorCount, MemoryCapacity, VirtualMachinePath, VirtualHardDiskPath"; Type="PowerShell"; FeatureName="Hyper-V"; Category="Hyper-V"},
    @{Name="Hyper-V Virtuelle Maschinen"; Command="Get-VM | Select-Object Name, State, CPUUsage, MemoryAssigned, Uptime, Version, Generation"; Type="PowerShell"; FeatureName="Hyper-V"; Category="Hyper-V"},
    @{Name="Hyper-V Switches"; Command="Get-VMSwitch | Select-Object Name, SwitchType, NetAdapterInterfaceDescription, AllowManagementOS"; Type="PowerShell"; FeatureName="Hyper-V"; Category="Hyper-V"},
    @{Name="Hyper-V Snapshots"; Command="Get-VMSnapshot * | Select-Object VMName, Name, SnapshotType, CreationTime, ParentSnapshotName"; Type="PowerShell"; FeatureName="Hyper-V"; Category="Hyper-V"},
    @{Name="Hyper-V Integration Services"; Command="Get-VM | Get-VMIntegrationService | Select-Object VMName, Name, Enabled, PrimaryStatusDescription"; Type="PowerShell"; FeatureName="Hyper-V"; Category="Hyper-V"},
    @{Name="Hyper-V Replikation"; Command="Get-VMReplication | Select-Object VMName, State, Mode, FrequencySec, PrimaryServer, ReplicaServer"; Type="PowerShell"; FeatureName="Hyper-V"; Category="Hyper-V"},
    
    # === FAILOVER CLUSTER AUDITS ===
    @{Name="Cluster Informationen"; Command="Get-Cluster | Select-Object Name, Domain, AddEvictDelay, BackupInProgress, BlockCacheSize"; Type="PowerShell"; FeatureName="Failover-Clustering"; Category="Cluster"},
    @{Name="Cluster Nodes"; Command="Get-ClusterNode | Select-Object Name, State, Type, ID"; Type="PowerShell"; FeatureName="Failover-Clustering"; Category="Cluster"},
    @{Name="Cluster Resources"; Command="Get-ClusterResource | Select-Object Name, ResourceType, State, OwnerNode, OwnerGroup"; Type="PowerShell"; FeatureName="Failover-Clustering"; Category="Cluster"},
    @{Name="Cluster Shared Volumes"; Command="Get-ClusterSharedVolume | Select-Object Name, State, Node, SharedVolumeInfo"; Type="PowerShell"; FeatureName="Failover-Clustering"; Category="Cluster"},
    @{Name="Cluster Networks"; Command="Get-ClusterNetwork | Select-Object Name, Role, State, Address, AddressMask"; Type="PowerShell"; FeatureName="Failover-Clustering"; Category="Cluster"},
    @{Name="Cluster Validation Report"; Command="Test-Cluster -ReportName 'C:\\temp\\ClusterValidation.htm' -Include 'Storage','Network','System Configuration','Inventory'"; Type="PowerShell"; FeatureName="Failover-Clustering"; Category="Cluster"},
    
    # === WINDOWS SERVER UPDATE SERVICES (WSUS) ===
    @{Name="WSUS Server Konfiguration"; Command="Get-WsusServer | Select-Object Name, PortNumber, ServerProtocolVersion, DatabasePath"; Type="PowerShell"; FeatureName="UpdateServices"; Category="WSUS"},
    @{Name="WSUS Update Kategorien"; Command="Get-WsusServer | Get-WsusClassification | Select-Object Classification, ID"; Type="PowerShell"; FeatureName="UpdateServices"; Category="WSUS"},
    @{Name="WSUS Computer Gruppen"; Command="Get-WsusServer | Get-WsusComputerTargetGroup | Select-Object Name, ID, ComputerTargets"; Type="PowerShell"; FeatureName="UpdateServices"; Category="WSUS"},
    @{Name="WSUS Synchronisation Status"; Command="Get-WsusServer | Get-WsusSubscription | Select-Object LastSynchronizationTime, SynchronizeAutomatically, NumberOfSynchronizations"; Type="PowerShell"; FeatureName="UpdateServices"; Category="WSUS"},
    
    # === FILE SERVICES ===
    @{Name="File Shares"; Command="Get-SmbShare | Select-Object Name, Path, Description, ShareType, ShareState"; Type="PowerShell"; FeatureName="FS-FileServer"; Category="FileServices"},
    @{Name="DFS Namespaces"; Command="Get-DfsnRoot | Select-Object Path, Type, State, Description"; Type="PowerShell"; FeatureName="FS-DFS-Namespace"; Category="FileServices"},
    @{Name="DFS Replication Groups"; Command="Get-DfsReplicationGroup | Select-Object GroupName, State, Description"; Type="PowerShell"; FeatureName="FS-DFS-Replication"; Category="FileServices"},
    @{Name="File Server Resource Manager Quotas"; Command="Get-FsrmQuota | Select-Object Path, Size, SoftLimit, Usage, Description"; Type="PowerShell"; FeatureName="FS-Resource-Manager"; Category="FileServices"},
    @{Name="Shadow Copies"; Command="Get-CimInstance -ClassName Win32_ShadowCopy | Select-Object VolumeName, InstallDate, Count"; Type="PowerShell"; FeatureName="FS-FileServer"; Category="FileServices"},
    
    # === PRINT SERVICES ===
    @{Name="Print Server Drucker"; Command="Get-Printer | Select-Object Name, DriverName, PortName, Shared, Published, PrinterStatus"; Type="PowerShell"; FeatureName="Print-Services"; Category="PrintServices"},
    @{Name="Print Server Treiber"; Command="Get-PrinterDriver | Select-Object Name, Manufacturer, DriverVersion, PrinterEnvironment"; Type="PowerShell"; FeatureName="Print-Services"; Category="PrintServices"},
    @{Name="Print Server Ports"; Command="Get-PrinterPort | Select-Object Name, Description, PortMonitor, PortType"; Type="PowerShell"; FeatureName="Print-Services"; Category="PrintServices"},
    
    # === REMOTE DESKTOP SERVICES ===
    @{Name="RDS Server Informationen"; Command="Get-RDServer | Select-Object Server, Roles"; Type="PowerShell"; FeatureName="RDS-RD-Server"; Category="RDS"},
    @{Name="RDS Session Collections"; Command="Get-RDSessionCollection | Select-Object CollectionName, CollectionDescription, Size"; Type="PowerShell"; FeatureName="RDS-RD-Server"; Category="RDS"},
    @{Name="RDS User Sessions"; Command="Get-RDUserSession | Select-Object CollectionName, DomainName, UserName, SessionState"; Type="PowerShell"; FeatureName="RDS-RD-Server"; Category="RDS"},
    @{Name="RDS Licensing"; Command="Get-RDLicenseConfiguration | Select-Object Mode, LicenseServer"; Type="PowerShell"; FeatureName="RDS-Licensing"; Category="RDS"},
    
    # === CERTIFICATE SERVICES ===
    @{Name="Certificate Authority Info"; Command="certutil -getconfig"; Type="CMD"; FeatureName="ADCS-Cert-Authority"; Category="PKI"},
    @{Name="CA Certificate Templates"; Command="certutil -template"; Type="CMD"; FeatureName="ADCS-Cert-Authority"; Category="PKI"},
    @{Name="Certificate Store - Personal"; Command="Get-ChildItem Cert:\\LocalMachine\\My | Select-Object Subject, Issuer, NotAfter, Thumbprint"; Type="PowerShell"; Category="PKI"},
    @{Name="Certificate Store - Root"; Command="Get-ChildItem Cert:\\LocalMachine\\Root | Select-Object Subject, Issuer, NotAfter, Thumbprint"; Type="PowerShell"; Category="PKI"},
    
    # === ERWEITERTE SICHERHEITS-AUDITS ===
    @{Name="Security Event Log (Letzte 100)"; Command="Get-WinEvent -FilterHashtable @{LogName='Security'} -MaxEvents 100 | Select-Object TimeCreated, Id, LevelDisplayName, UserId, Message"; Type="PowerShell"; Category="Security"},
    @{Name="Failed Logon Attempts"; Command="Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 50 | Select-Object TimeCreated, Message"; Type="PowerShell"; Category="Security"},
    @{Name="Account Lockouts"; Command="Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4740} -MaxEvents 50 | Select-Object TimeCreated, Message"; Type="PowerShell"; Category="Security"},
    @{Name="Privilege Use Auditing"; Command="Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4672,4673,4674} -MaxEvents 50 | Select-Object TimeCreated, Id, Message"; Type="PowerShell"; Category="Security"},
    @{Name="Unsecure LDAP Binds"; Command="Get-WinEvent -FilterHashtable @{LogName='Directory Service'; ID=2889} -MaxEvents 20 | Select-Object TimeCreated, Message"; Type="PowerShell"; FeatureName="AD-Domain-Services"; Category="Security"},
    
    # === ACTIVE DIRECTORY FEDERATION SERVICES (ADFS) ===
    @{Name="ADFS Server Konfiguration"; Command="Get-AdfsProperties | Select-Object DisplayName, HostName, HttpPort, HttpsPort, TlsClientPort"; Type="PowerShell"; FeatureName="ADFS-Federation"; Category="ADFS"},
    @{Name="ADFS Relying Party Trusts"; Command="Get-AdfsRelyingPartyTrust | Select-Object Name, Enabled, Identifier, IssuanceAuthorizationRules"; Type="PowerShell"; FeatureName="ADFS-Federation"; Category="ADFS"},
    @{Name="ADFS Claims Provider Trusts"; Command="Get-AdfsClaimsProviderTrust | Select-Object Name, Enabled, Identifier, AcceptanceTransformRules"; Type="PowerShell"; FeatureName="ADFS-Federation"; Category="ADFS"},
    @{Name="ADFS Certificates"; Command="Get-AdfsCertificate | Select-Object CertificateType, Thumbprint, Subject, NotAfter"; Type="PowerShell"; FeatureName="ADFS-Federation"; Category="ADFS"},
    @{Name="ADFS Endpoints"; Command="Get-AdfsEndpoint | Select-Object AddressPath, Enabled, Protocol, SecurityMode"; Type="PowerShell"; FeatureName="ADFS-Federation"; Category="ADFS"},
    
    # === ACTIVE DIRECTORY LIGHTWEIGHT DIRECTORY SERVICES (ADLDS) ===
    @{Name="ADLDS Instances"; Command="Get-CimInstance -ClassName Win32_Service | Where-Object {`$_.Name -like 'ADAM_*'} | Select-Object Name, State, StartMode, PathName"; Type="PowerShell"; FeatureName="ADLDS"; Category="ADLDS"},
    @{Name="ADLDS Configuration"; Command="dsdbutil -c 'activate instance `$instancename' quit | Out-String"; Type="CMD"; FeatureName="ADLDS"; Category="ADLDS"},
    
    # === ACTIVE DIRECTORY RIGHTS MANAGEMENT SERVICES (ADRMS) ===
    @{Name="ADRMS Cluster Info"; Command="Get-RmsCluster | Select-Object ClusterName, ClusterUrl, Version"; Type="PowerShell"; FeatureName="ADRMS"; Category="ADRMS"},
    @{Name="ADRMS Server Info"; Command="Get-RmsServer | Select-Object Name, ClusterName, Version, IsConnected"; Type="PowerShell"; FeatureName="ADRMS"; Category="ADRMS"},
    @{Name="ADRMS Templates"; Command="Get-RmsTemplate | Select-Object Name, Description, Validity, Created"; Type="PowerShell"; FeatureName="ADRMS"; Category="ADRMS"},
    
    # === DEVICE HEALTH ATTESTATION SERVICE ===
    @{Name="Device Health Attestation Service"; Command="Get-DHASActiveEncryptionCertificate; Get-DHASActiveSigningCertificate"; Type="PowerShell"; FeatureName="DeviceHealthAttestationService"; Category="DeviceAttestation"},
    
    # === VOLUME ACTIVATION SERVICES ===
    @{Name="KMS Server Konfiguration"; Command="slmgr /dlv; cscript C:\\Windows\\System32\\slmgr.vbs /dli"; Type="CMD"; FeatureName="VolumeActivation"; Category="VolumeActivation"},
    @{Name="KMS Client Status"; Command="Get-CimInstance -ClassName SoftwareLicensingProduct | Where-Object {`$_.LicenseStatus -eq 1} | Select-Object Name, Description, LicenseStatus"; Type="PowerShell"; FeatureName="VolumeActivation"; Category="VolumeActivation"},
    
    # === WINDOWS SERVER BACKUP ===
    @{Name="Windows Server Backup Policies"; Command="Get-WBPolicy | Select-Object PolicyState, BackupTargets, FilesSpecsToBackup"; Type="PowerShell"; FeatureName="Windows-Server-Backup"; Category="Backup"},
    @{Name="Windows Server Backup Jobs"; Command="Get-WBJob -Previous 10 | Select-Object JobType, JobState, StartTime, EndTime, HResult"; Type="PowerShell"; FeatureName="Windows-Server-Backup"; Category="Backup"},
    @{Name="Windows Server Backup Disks"; Command="Get-WBDisk | Select-Object DiskNumber, Label, InternalDiskNumber"; Type="PowerShell"; FeatureName="Windows-Server-Backup"; Category="Backup"},
    
    # === NETWORK POLICY AND ACCESS SERVICES (NPAS) ===
    @{Name="NPS Server Konfiguration"; Command="netsh nps show config"; Type="CMD"; FeatureName="NPAS"; Category="NPAS"},
    @{Name="NPS Network Policies"; Command="Get-NpsNetworkPolicy | Select-Object PolicyName, Enabled, ProcessingOrder, ConditionText"; Type="PowerShell"; FeatureName="NPAS"; Category="NPAS"},
    @{Name="NPS Connection Request Policies"; Command="Get-NpsConnectionRequestPolicy | Select-Object Name, Enabled, ProcessingOrder"; Type="PowerShell"; FeatureName="NPAS"; Category="NPAS"},
    @{Name="NPS RADIUS Clients"; Command="Get-NpsRadiusClient | Select-Object Name, Address, SharedSecret, VendorName"; Type="PowerShell"; FeatureName="NPAS"; Category="NPAS"},
    
    # === HOST GUARDIAN SERVICE ===
    @{Name="HGS Service Info"; Command="Get-HgsServer | Select-Object Name, State, Version"; Type="PowerShell"; FeatureName="HostGuardianServiceRole"; Category="HGS"},
    @{Name="HGS Attestation Policies"; Command="Get-HgsAttestationPolicy | Select-Object Name, PolicyVersion, Stage"; Type="PowerShell"; FeatureName="HostGuardianServiceRole"; Category="HGS"},
    
    # === REMOTE ACCESS SERVICES ===
    @{Name="DirectAccess Konfiguration"; Command="Get-DAServer | Select-Object ConnectToAddress, TunnelType, AuthenticationMethod"; Type="PowerShell"; FeatureName="RemoteAccess"; Category="RemoteAccess"},
    @{Name="VPN Server Konfiguration"; Command="Get-VpnServerConfiguration | Select-Object TunnelType, EncryptionLevel, IdleDisconnectSeconds"; Type="PowerShell"; FeatureName="RemoteAccess"; Category="RemoteAccess"},
    @{Name="Routing Table"; Command="Get-NetRoute | Select-Object DestinationPrefix, NextHop, RouteMetric, Protocol"; Type="PowerShell"; FeatureName="RemoteAccess"; Category="RemoteAccess"},
    
    # === WINDOWS INTERNAL DATABASE ===
    @{Name="Windows Internal Database Instanzen"; Command="Get-CimInstance -ClassName Win32_Service | Where-Object {`$_.Name -like '*MSSQL*MICROSOFT*'} | Select-Object Name, State, StartMode"; Type="PowerShell"; FeatureName="Windows-Internal-Database"; Category="InternalDB"},
    @{Name="SQL Server Express Instanzen"; Command="Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\Instance Names\\SQL' -ErrorAction SilentlyContinue"; Type="PowerShell"; FeatureName="Windows-Internal-Database"; Category="InternalDB"},
    
    # === WINDOWS DEFENDER FEATURES ===
    @{Name="Windows Defender Status"; Command="Get-MpComputerStatus | Select-Object AntivirusEnabled, AMServiceEnabled, RealTimeProtectionEnabled, IoavProtectionEnabled"; Type="PowerShell"; FeatureName="Windows-Defender-Features"; Category="WindowsDefender"},
    @{Name="Windows Defender Preferences"; Command="Get-MpPreference | Select-Object DisableRealtimeMonitoring, DisableIntrusionPreventionSystem, DisableIOAVProtection"; Type="PowerShell"; FeatureName="Windows-Defender-Features"; Category="WindowsDefender"},
    @{Name="Windows Defender Threats"; Command="Get-MpThreatDetection | Select-Object -First 20 | Select-Object ThreatID, ActionSuccess, DetectionTime, ThreatName"; Type="PowerShell"; FeatureName="Windows-Defender-Features"; Category="WindowsDefender"},
    
    # === WINDOWS PROCESS ACTIVATION SERVICE (WAS) ===
    @{Name="WAS Service Status"; Command="Get-Service WAS | Select-Object Name, Status, StartType, ServiceType"; Type="PowerShell"; FeatureName="Windows-Process-Activation-Service"; Category="WAS"},
    @{Name="Application Pool WAS"; Command="Get-IISAppPool | Select-Object Name, State, ProcessModel, Enable32BitAppOnWin64"; Type="PowerShell"; FeatureName="Windows-Process-Activation-Service"; Category="WAS"},
    
    # === WINDOWS SEARCH SERVICE ===
    @{Name="Windows Search Service"; Command="Get-Service WSearch | Select-Object Name, Status, StartType"; Type="PowerShell"; FeatureName="Windows-Search-Service"; Category="SearchService"},
    @{Name="Search Indexer Status"; Command="Get-CimInstance -ClassName Win32_Service | Where-Object Name -eq 'WSearch' | Select-Object Name, State, ProcessId"; Type="PowerShell"; FeatureName="Windows-Search-Service"; Category="SearchService"},
    
    # === ERWEITERTE SYSTEM-AUDITS (basierend auf GitHub Best Practices) ===
    @{Name="Lokale Administratoren"; Command="net localgroup administrators"; Type="CMD"; Category="Security"},
    @{Name="Guest Account Status"; Command="net user guest"; Type="CMD"; Category="Security"},
    @{Name="Shared Folders"; Command="net share"; Type="CMD"; Category="FileSharing"},
    @{Name="Benutzer Profile"; Command="Get-ChildItem C:\\Users | Select-Object Name, CreationTime, LastWriteTime"; Type="PowerShell"; Category="UserProfiles"},
    @{Name="Windows Firewall Profile"; Command="netsh advfirewall show allprofiles"; Type="CMD"; Category="Firewall"},
    @{Name="Power Management"; Command="powercfg /a"; Type="CMD"; Category="PowerManagement"},
    @{Name="Credential Manager"; Command="vaultcmd /listschema; vaultcmd /list"; Type="CMD"; Category="CredentialManager"},
    @{Name="Audit Policy Settings"; Command="auditpol.exe /get /category:*"; Type="CMD"; Category="AuditPolicy"},
    @{Name="Group Policy Results"; Command="gpresult /r"; Type="CMD"; Category="GroupPolicy"},
    @{Name="Installed Software (Registry)"; Command="Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate"; Type="PowerShell"; Category="InstalledSoftware"},
    @{Name="Environment Variables"; Command="Get-ChildItem Env: | Sort-Object Name"; Type="PowerShell"; Category="Environment"},
    
    # === AD HEALTH CHECK (basierend auf Microsoft DevBlogs) ===
    @{Name="AD DHCP Server in AD"; Command="Get-ADObject -SearchBase (`"cn=configuration,`" + (Get-ADDomain).DistinguishedName) -Filter `"objectclass -eq 'dhcpclass' -AND Name -ne 'dhcproot'`" | Select-Object Name"; Type="PowerShell"; FeatureName="AD-Domain-Services"; Category="Active-Directory"},
    @{Name="AD Service Dependencies Health"; Command="`$Services='DNS','DFS Replication','Intersite Messaging','Kerberos Key Distribution Center','NetLogon','Active Directory Domain Services'; ForEach (`$Service in `$Services) {Get-Service `$Service -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType}"; Type="PowerShell"; FeatureName="AD-Domain-Services"; Category="Active-Directory"},
    @{Name="AD DC Diagnostics"; Command="dcdiag /test:dns /e /v"; Type="CMD"; FeatureName="AD-Domain-Services"; Category="Active-Directory"},
    @{Name="AD Time Sync Status"; Command="w32tm /query /status"; Type="CMD"; FeatureName="AD-Domain-Services"; Category="Active-Directory"},
    @{Name="AD Sysvol Replication"; Command="dfsrdiag replicationstate /member:*"; Type="CMD"; FeatureName="AD-Domain-Services"; Category="Active-Directory"},
    
    # === WINDOWS SERVER ESSENTIALS ===
    @{Name="Server Essentials Dashboard"; Command="Get-WssUser | Select-Object UserName, FullName, Description, Enabled"; Type="PowerShell"; FeatureName="ServerEssentialsRole"; Category="ServerEssentials"},
    @{Name="Server Essentials Backup"; Command="Get-WssClientBackup | Select-Object ComputerName, LastBackupTime, LastSuccessfulBackupTime"; Type="PowerShell"; FeatureName="ServerEssentialsRole"; Category="ServerEssentials"},
    
    # === STORAGE MANAGEMENT ===
    @{Name="Storage Pools"; Command="Get-StoragePool | Select-Object FriendlyName, HealthStatus, OperationalStatus, TotalPhysicalCapacity"; Type="PowerShell"; FeatureName="Windows-Storage-Management"; Category="Storage"},
    @{Name="Virtual Disks"; Command="Get-VirtualDisk | Select-Object FriendlyName, HealthStatus, OperationalStatus, Size, AllocatedSize"; Type="PowerShell"; FeatureName="Windows-Storage-Management"; Category="Storage"},
    @{Name="Storage Spaces"; Command="Get-StorageSpace | Select-Object FriendlyName, HealthStatus, ProvisioningType, ResiliencySettingName"; Type="PowerShell"; FeatureName="Windows-Storage-Management"; Category="Storage"},
    @{Name="Physical Disks"; Command="Get-PhysicalDisk | Select-Object FriendlyName, HealthStatus, OperationalStatus, Size, MediaType"; Type="PowerShell"; FeatureName="Windows-Storage-Management"; Category="Storage"},
    
    # === MIGRATION SERVICES ===
    @{Name="Windows Server Migration Tools"; Command="Get-SmigServerFeature | Select-Object FeatureName, Status"; Type="PowerShell"; FeatureName="Windows-Server-Migration"; Category="Migration"},
    
    # === WINDOWS IDENTITY FOUNDATION ===
    @{Name="Windows Identity Foundation"; Command="Get-WindowsFeature Windows-Identity-Foundation | Select-Object Name, InstallState, FeatureType"; Type="PowerShell"; FeatureName="Windows-Identity-Foundation"; Category="Identity"}
)

# Erweiterte Verbindungsaudit-Befehle fuer umfassende Netzwerkanalyse
$connectionAuditCommands = @(
    # === NETZWERK-VERBINDUNGSBAUM ===
    @{Name="Verbindungsbaum (Aktive TCP)"; Command="Get-NetTCPConnection | Where-Object { `$_.State -eq 'Established' } | ForEach-Object { `$proc = Get-Process -Id `$_.OwningProcess -ErrorAction SilentlyContinue; [PSCustomObject]@{ LocalIP=`$_.LocalAddress; LocalPort=`$_.LocalPort; RemoteIP=`$_.RemoteAddress; RemotePort=`$_.RemotePort; Process=if(`$proc){`$proc.ProcessName}else{'N/A'}; PID=`$_.OwningProcess; User=if(`$proc){try{`$proc.StartInfo.UserName}catch{'System'}}else{'N/A'} } } | Sort-Object Process, RemoteIP"; Type="PowerShell"; Category="Verbindungsbaum"},
    @{Name="Netzwerk-Topologie-Map"; Command="`$adapters = Get-NetAdapter | Where-Object Status -eq 'Up'; `$routes = Get-NetRoute | Where-Object RouteMetric -lt 500; `$topology = @(); foreach(`$adapter in `$adapters) { `$ip = Get-NetIPAddress -InterfaceIndex `$adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1; if(`$ip) { `$gateway = `$routes | Where-Object { `$_.InterfaceIndex -eq `$adapter.InterfaceIndex -and `$_.DestinationPrefix -eq '0.0.0.0/0' } | Select-Object -First 1; `$topology += [PSCustomObject]@{ Interface=`$adapter.Name; MAC=`$adapter.MacAddress; IP=`$ip.IPAddress; Subnet=`$ip.PrefixLength; Gateway=if(`$gateway){`$gateway.NextHop}else{'N/A'}; Speed=`$adapter.LinkSpeed } } } `$topology | Format-Table -AutoSize"; Type="PowerShell"; Category="Verbindungsbaum"},
    @{Name="Prozess-Netzwerk-Zuordnung (Erweitert)"; Command="Get-NetTCPConnection | Group-Object OwningProcess | ForEach-Object { `$proc = Get-Process -Id `$_.Name -ErrorAction SilentlyContinue; `$connections = `$_.Group; [PSCustomObject]@{ PID=`$_.Name; ProcessName=if(`$proc){`$proc.ProcessName}else{'Unknown'}; ProcessPath=if(`$proc){try{`$proc.MainModule.FileName}catch{'N/A'}}else{'N/A'}; AnzahlVerbindungen=`$connections.Count; AktiveVerbindungen=(`$connections | Where-Object State -eq 'Established').Count; LauschtPorts=(`$connections | Where-Object State -eq 'Listen').Count; ExterneIPs=(`$connections | Where-Object { `$_.RemoteAddress -notmatch '^127\.|^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^::1|^fe80:' -and `$_.RemoteAddress -ne '0.0.0.0' -and `$_.RemoteAddress -ne '::' } | Select-Object -ExpandProperty RemoteAddress -Unique | Measure-Object).Count; StartZeit=if(`$proc){`$proc.StartTime}else{'N/A'} } } | Sort-Object AnzahlVerbindungen -Descending"; Type="PowerShell"; Category="Verbindungsbaum"},

    # === AKTIVE NETZWERKVERBINDUNGEN (Erweitert) ===
    @{Name="Alle TCP-Verbindungen (Performance)"; Command="Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, CreationTime | Sort-Object State, LocalPort"; Type="PowerShell"; Category="TCP-Connections"},
    @{Name="Etablierte TCP-Verbindungen"; Command="Get-NetTCPConnection -State Established | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, CreationTime"; Type="PowerShell"; Category="TCP-Connections"},
    @{Name="Lauschende Ports (Listen)"; Command="Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess | Sort-Object LocalPort"; Type="PowerShell"; Category="TCP-Connections"},
    @{Name="UDP-Endpunkte"; Command="Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess | Sort-Object LocalPort"; Type="PowerShell"; Category="UDP-Connections"},
    @{Name="Externe Verbindungen (Internet)"; Command="Get-NetTCPConnection | Where-Object {`$_.RemoteAddress -notmatch '^127\.|^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^::1|^fe80:' -and `$_.RemoteAddress -ne '0.0.0.0' -and `$_.RemoteAddress -ne '::'} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess"; Type="PowerShell"; Category="External-Connections"},
    
    # === ERWEITERTE PROZESS-NETZWERK ANALYSE ===
    @{Name="Top-Prozesse nach Verbindungen"; Command="Get-NetTCPConnection | Group-Object OwningProcess | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object { `$proc = Get-Process -Id `$_.Name -ErrorAction SilentlyContinue; [PSCustomObject]@{ PID=`$_.Name; Process=if(`$proc){`$proc.ProcessName}else{'Unknown'}; Verbindungen=`$_.Count; Established=(`$_.Group | Where-Object State -eq 'Established').Count; Listen=(`$_.Group | Where-Object State -eq 'Listen').Count } }"; Type="PowerShell"; Category="Process-Network"},
    @{Name="Verdächtige Prozess-Verbindungen"; Command="Get-NetTCPConnection | Where-Object { `$_.State -eq 'Established' -and `$_.RemoteAddress -notmatch '^127\.|^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.' } | ForEach-Object { `$proc = Get-Process -Id `$_.OwningProcess -ErrorAction SilentlyContinue; if(`$proc -and `$proc.Path -notmatch 'Windows|Program Files') { [PSCustomObject]@{ Process=`$proc.ProcessName; PID=`$_.OwningProcess; Path=try{`$proc.MainModule.FileName}catch{'N/A'}; RemoteIP=`$_.RemoteAddress; RemotePort=`$_.RemotePort; Company=try{`$proc.Company}catch{'N/A'} } } } | Sort-Object Process"; Type="PowerShell"; Category="Process-Network"},
    @{Name="Netzwerk-Statistiken pro Prozess"; Command="Get-Process | Where-Object { `$_.Id -ne 0 } | ForEach-Object { `$pid = `$_.Id; `$tcpConns = @(Get-NetTCPConnection | Where-Object OwningProcess -eq `$pid); `$udpConns = @(Get-NetUDPEndpoint | Where-Object OwningProcess -eq `$pid); if(`$tcpConns.Count -gt 0 -or `$udpConns.Count -gt 0) { [PSCustomObject]@{ ProcessName=`$_.ProcessName; PID=`$pid; TCP_Verbindungen=`$tcpConns.Count; UDP_Verbindungen=`$udpConns.Count; CPU_Percent=0; RAM_MB=[math]::Round(`$_.WorkingSet64/1MB,2) } } } | Sort-Object TCP_Verbindungen -Descending"; Type="PowerShell"; Category="Process-Network"},

    # === LOKALE GERÄTE UND NETZWERK-ERKENNUNG ===
    @{Name="ARP-Cache (Lokale Geräte)"; Command="Get-NetNeighbor | Where-Object State -ne 'Unreachable' | Select-Object IPAddress, MacAddress, State, InterfaceAlias | Sort-Object IPAddress"; Type="PowerShell"; Category="Local-Devices"},
    @{Name="MAC-Adressen-Analyse"; Command="Get-NetNeighbor | Where-Object { `$_.MacAddress -ne '00-00-00-00-00-00' -and `$_.State -ne 'Unreachable' } | ForEach-Object { `$vendor = switch -Regex (`$_.MacAddress.Substring(0,8)) { '^00-50-56' {'VMware'}; '^00-0C-29' {'VMware'}; '^08-00-27' {'VirtualBox'}; '^00-15-5D' {'Microsoft Hyper-V'}; '^00-1B-21' {'Dell'}; '^00-25-90' {'Dell'}; '^D4-BE-D9' {'Dell'}; '^B8-2A-72' {'Dell'}; '^70-B3-D5' {'HP'}; '^3C-D9-2B' {'HP'}; '^94-57-A5' {'HP'}; default {'Unknown'} }; [PSCustomObject]@{ IP=`$_.IPAddress; MAC=`$_.MacAddress; Vendor=`$vendor; State=`$_.State; Interface=`$_.InterfaceAlias } } | Sort-Object Vendor, IP"; Type="PowerShell"; Category="Local-Devices"},
    @{Name="DHCP-Lease-Informationen"; Command="try { Get-DhcpServerv4Lease -ComputerName localhost | Select-Object IPAddress, ClientId, HostName, AddressState, LeaseExpiryTime | Sort-Object IPAddress } catch { 'DHCP-Server nicht verfügbar oder keine Berechtigung' }"; Type="PowerShell"; Category="Local-Devices"},
    @{Name="Wireless-Netzwerke (Falls verfügbar)"; Command="try { netsh wlan show profiles } catch { 'Wireless-Adapter nicht verfügbar' }"; Type="CMD"; Category="Local-Devices"},

    # === DNS UND NETZWERK-AUFLÖSUNG ===
    @{Name="DNS-Cache-Analyse"; Command="Get-DnsClientCache | Where-Object { `$_.Type -eq 'A' } | Select-Object Name, Data, TTL, Section | Sort-Object Name"; Type="PowerShell"; Category="DNS-Info"},
    @{Name="DNS-Server-Konfiguration"; Command="Get-DnsClientServerAddress | Where-Object { `$_.ServerAddresses.Count -gt 0 } | Select-Object InterfaceAlias, @{Name='DNS_Server';Expression={`$_.ServerAddresses -join ', '}} | Sort-Object InterfaceAlias"; Type="PowerShell"; Category="DNS-Info"},
    @{Name="Reverse-DNS-Lookup (Top-IPs)"; Command="`$topIPs = Get-NetTCPConnection | Where-Object { `$_.RemoteAddress -notmatch '^127\.|^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^::1|^fe80:' -and `$_.RemoteAddress -ne '0.0.0.0' -and `$_.RemoteAddress -ne '::' } | Group-Object RemoteAddress | Sort-Object Count -Descending | Select-Object -First 10; `$topIPs | ForEach-Object { `$ip = `$_.Name; try { `$hostname = [System.Net.Dns]::GetHostEntry(`$ip).HostName } catch { `$hostname = 'N/A' }; [PSCustomObject]@{ IP=`$ip; Hostname=`$hostname; Verbindungen=`$_.Count } } | Sort-Object Verbindungen -Descending"; Type="PowerShell"; Category="DNS-Info"},
    @{Name="Domänen-DNS-Informationen"; Command="nslookup `$env:USERDNSDOMAIN 2>null | Select-String -Pattern 'Address|Server'"; Type="CMD"; Category="DNS-Info"},

    # === GEO-IP UND EXTERNE ANALYSE ===
    @{Name="Geo-IP-Analyse (Externe IPs)"; Command="`$externalIPs = Get-NetTCPConnection | Where-Object { `$_.RemoteAddress -notmatch '^127\.|^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^::1|^fe80:' -and `$_.RemoteAddress -ne '0.0.0.0' -and `$_.RemoteAddress -ne '::' } | Select-Object -ExpandProperty RemoteAddress -Unique | Select-Object -First 5; `$externalIPs | ForEach-Object { `$ip = `$_; [PSCustomObject]@{ IP=`$ip; Land='Online-Analyse erforderlich'; Region='API-Limit'; Stadt='Verfügbar'; ISP='ipinfo.io'; Hostname='Manual-Check' } }"; Type="PowerShell"; Category="Geo-IP"},
    @{Name="Bedrohungsanalyse (Blacklist-Check)"; Command="`$suspiciousIPs = Get-NetTCPConnection | Where-Object { `$_.RemoteAddress -notmatch '^127\.|^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^::1|^fe80:' -and `$_.RemoteAddress -ne '0.0.0.0' -and `$_.RemoteAddress -ne '::' } | Select-Object -ExpandProperty RemoteAddress -Unique; `$suspiciousIPs | ForEach-Object { `$ip = `$_; `$isPrivate = `$ip -match '^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.'; `$isSuspicious = `$ip -match '^(185\.243\.|91\.234\.|77\.83\.)' -or `$ip -match '^(193\.0\.14\.|208\.67\.222\.)'; [PSCustomObject]@{ IP=`$ip; Type=if(`$isPrivate){'Privat'}elseif(`$isSuspicious){'⚠️ Verdächtig'}else{'Public'}; Port_Count=(Get-NetTCPConnection | Where-Object RemoteAddress -eq `$ip).Count } } | Sort-Object Type, IP"; Type="PowerShell"; Category="Geo-IP"},

    # === FIREWALL UND SICHERHEIT ===
    @{Name="Windows-Firewall-Status"; Command="Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogFileName"; Type="PowerShell"; Category="Firewall-Logs"},
    @{Name="Firewall-Regeln (Aktiv)"; Command="Get-NetFirewallRule | Where-Object { `$_.Enabled -eq 'True' -and `$_.Direction -eq 'Inbound' } | Select-Object DisplayName, Direction, Action, Protocol, LocalPort | Sort-Object Protocol, LocalPort | Select-Object -First 50"; Type="PowerShell"; Category="Firewall-Logs"},
    @{Name="Firewall-Verbindungslogs"; Command="try { `$events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'} -MaxEvents 50 -ErrorAction Stop 2>`$null; if(`$events) { `$events | Select-Object TimeCreated, Id, LevelDisplayName, Message | Sort-Object TimeCreated -Descending } else { 'Keine Firewall-Events gefunden' } } catch [System.Exception] { 'Firewall-Logs nicht verfügbar oder deaktiviert - ' + `$_.Exception.Message.Split('.')[0] }"; Type="PowerShell"; Category="Firewall-Logs"},
    @{Name="Blockierte Verbindungen"; Command="try { `$events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5157} -MaxEvents 20 -ErrorAction Stop 2>`$null; if(`$events) { `$events | ForEach-Object { `$xml = [xml]`$_.ToXml(); [PSCustomObject]@{ Zeit=`$_.TimeCreated; Prozess=`$xml.Event.EventData.Data | Where-Object Name -eq 'Application' | Select-Object -ExpandProperty '#text'; Quelle=`$xml.Event.EventData.Data | Where-Object Name -eq 'SourceAddress' | Select-Object -ExpandProperty '#text'; Ziel=`$xml.Event.EventData.Data | Where-Object Name -eq 'DestAddress' | Select-Object -ExpandProperty '#text'; Port=`$xml.Event.EventData.Data | Where-Object Name -eq 'DestPort' | Select-Object -ExpandProperty '#text' } } | Sort-Object Zeit -Descending } else { 'Keine blockierten Verbindungen (Event-ID 5157) gefunden' } } catch [System.Exception] { 'Sicherheitslogs für blockierte Verbindungen nicht verfügbar - Event-ID 5157 nicht aktiviert oder keine Events vorhanden' }"; Type="PowerShell"; Category="Firewall-Logs"},

    # === NETZWERK-EVENTS UND MONITORING ===
    @{Name="Netzwerk-Sicherheitsereignisse"; Command="try { `$events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5156} -MaxEvents 30 -ErrorAction Stop 2>`$null; if(`$events) { `$events | Select-Object TimeCreated, Id, LevelDisplayName, Message | Sort-Object TimeCreated -Descending } else { 'Keine Netzwerk-Sicherheitsereignisse (Event-ID 5156) gefunden - Logging möglicherweise deaktiviert' } } catch [System.Exception] { 'Netzwerk-Sicherheitslogs nicht verfügbar - Event-ID 5156 erfordert aktivierte Firewall-Logging-Richtlinie' }"; Type="PowerShell"; Category="Network-Events"},
    @{Name="Netzwerk-Adapter-Events"; Command="try { `$events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Kernel-Network/Analytic'} -MaxEvents 20 -ErrorAction Stop 2>`$null; if(`$events) { `$events | Select-Object TimeCreated, Id, LevelDisplayName, Message | Sort-Object TimeCreated -Descending } else { 'Keine Kernel-Network-Events gefunden - Analytisches Log möglicherweise deaktiviert' } } catch [System.Exception] { 'Kernel-Network-Logs nicht verfügbar - Analytische Logs müssen in der Ereignisanzeige aktiviert werden' }"; Type="PowerShell"; Category="Network-Events"},
    @{Name="Prozess-Netzwerk-Events"; Command="try { `$events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Kernel-Process/Analytic'} -MaxEvents 25 -ErrorAction Stop 2>`$null; if(`$events) { `$networkEvents = `$events | Where-Object { `$_.Message -like '*network*' -or `$_.Message -like '*socket*' }; if(`$networkEvents) { `$networkEvents | Select-Object TimeCreated, Id, ProcessId, Message | Sort-Object TimeCreated -Descending } else { 'Keine Prozess-Netzwerk-Events in den letzten 25 Events gefunden' } } else { 'Keine Kernel-Process-Events gefunden - Analytisches Log möglicherweise deaktiviert' } } catch [System.Exception] { 'Prozess-Events nicht verfügbar - Analytische Logs müssen in der Ereignisanzeige aktiviert werden' }"; Type="PowerShell"; Category="Network-Events"},

    # === ACTIVE DIRECTORY UND DOMÄNEN-INFORMATIONEN ===
    @{Name="Domänen-Controller-Informationen"; Command="try { Get-ADDomainController -Discover -Service ADWS,KDC,TimeService | Select-Object Name, IPv4Address, Site, OperatingSystem, Domain } catch { try { nltest /dclist:`$env:USERDNSDOMAIN } catch { 'AD-Modul nicht verfügbar' } }"; Type="PowerShell"; Category="Domain-Users"},
    @{Name="Privilegierte AD-Gruppen"; Command="try { @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators') | ForEach-Object { `$group = `$_; try { Get-ADGroupMember -Identity `$group | Select-Object @{Name='Group';Expression={`$group}}, Name, SamAccountName, objectClass } catch { [PSCustomObject]@{Group=`$group; Name='Gruppe nicht gefunden'; SamAccountName='N/A'; objectClass='N/A'} } } } catch { 'AD-PowerShell-Modul nicht verfügbar' }"; Type="PowerShell"; Category="Domain-Users"},
    @{Name="Kürzliche AD-Anmeldungen"; Command="try { `$events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 50 -ErrorAction Stop 2>`$null; if(`$events) { `$filtered = `$events | Where-Object { `$_.Message -notlike '*ANONYMOUS*' }; if(`$filtered) { `$filtered | ForEach-Object { `$msg = `$_.Message; `$user = if(`$msg -match 'Account Name:\\s+([^\\r\\n]+)') { `$matches[1] } else { 'Unknown' }; `$workstation = if(`$msg -match 'Workstation Name:\\s+([^\\r\\n]+)') { `$matches[1] } else { 'Unknown' }; [PSCustomObject]@{ Zeit=`$_.TimeCreated; Benutzer=`$user; Workstation=`$workstation; LogonType=if(`$msg -match 'Logon Type:\\s+(\\d+)') { `$matches[1] } else { 'Unknown' } } } } | Where-Object { `$_.Benutzer -ne '-' -and `$_.Benutzer -ne 'ANONYMOUS LOGON' } | Sort-Object Zeit -Descending | Select-Object -First 20 } else { 'Keine relevanten Anmelde-Events (ohne ANONYMOUS) gefunden' } } else { 'Keine Anmelde-Events (Event-ID 4624) gefunden' } } catch [System.Exception] { 'Anmelde-Sicherheitslogs nicht verfügbar oder deaktiviert' }"; Type="PowerShell"; Category="Domain-Users"},
    @{Name="LDAP-Verbindungstests"; Command="try { `$domain = `$env:USERDNSDOMAIN; if(`$domain) { `$dcIP = (nslookup `$domain 2>null | Select-String -Pattern '\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}' | Select-Object -First 1).Matches.Value; if(`$dcIP) { Test-NetConnection -ComputerName `$dcIP -Port 389; Test-NetConnection -ComputerName `$dcIP -Port 636 } else { 'Domain-Controller-IP nicht ermittelbar' } } else { 'Nicht in einer Domäne' } } catch { 'LDAP-Test fehlgeschlagen' }"; Type="PowerShell"; Category="Domain-Users"},

    # === REMOTE-SESSIONS UND RDP ===
    @{Name="Remote-Desktop-Verbindungen"; Command="try { `$events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'} -MaxEvents 30 -ErrorAction Stop 2>`$null; if(`$events) { `$events | Select-Object TimeCreated, Id, LevelDisplayName, Message | Sort-Object TimeCreated -Descending } else { 'Keine Terminal-Services-Events gefunden' } } catch [System.Exception] { 'Terminal-Services-Logs nicht verfügbar oder deaktiviert' }"; Type="PowerShell"; Category="Remote-Sessions"},
    @{Name="SMB-Verbindungen"; Command="try { Get-SmbConnection | Select-Object ServerName, ShareName, UserName, Dialect } catch { 'SMB-Informationen nicht verfügbar' }"; Type="PowerShell"; Category="Remote-Sessions"},
    @{Name="SMB-Freigaben-Zugriffe"; Command="try { `$events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-SmbServer/Security'} -MaxEvents 50 -ErrorAction Stop 2>`$null; if(`$events) { `$events | Select-Object TimeCreated, Id, Message | Sort-Object TimeCreated -Descending } else { 'Keine SMB-Server-Security-Events gefunden' } } catch [System.Exception] { 'SMB-Security-Logs nicht verfügbar oder deaktiviert' }"; Type="PowerShell"; Category="Remote-Sessions"},
    @{Name="Aktive Terminal-Sessions"; Command="try { quser 2>`$null } catch { try { query session } catch { 'Terminal-Session-Abfrage nicht verfügbar' } }"; Type="CMD"; Category="Remote-Sessions"},

    # === ERWEITERTE NETZWERK-TOPOLOGIE ===
    @{Name="Routing-Tabelle (Detailliert)"; Command="Get-NetRoute | Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric, Protocol, @{Name='NetworkCategory';Expression={if(`$_.DestinationPrefix -eq '0.0.0.0/0'){'Default Gateway'}elseif(`$_.DestinationPrefix -like '169.254.*'){'APIPA'}elseif(`$_.DestinationPrefix -like '224.*'){'Multicast'}else{'Network Route'}}} | Sort-Object RouteMetric, DestinationPrefix"; Type="PowerShell"; Category="Network-Topology"},
    @{Name="Netzwerk-Interface-Statistiken"; Command="Get-NetAdapterStatistics | Select-Object Name, @{Name='Empfangen_GB';Expression={[math]::Round(`$_.BytesReceived/1GB,3)}}, @{Name='Gesendet_GB';Expression={[math]::Round(`$_.BytesSent/1GB,3)}}, @{Name='Pakete_Empfangen';Expression={`$_.PacketsReceived}}, @{Name='Pakete_Gesendet';Expression={`$_.PacketsSent}}, @{Name='Fehler_Eingehend';Expression={`$_.InboundErrors}}, @{Name='Fehler_Ausgehend';Expression={`$_.OutboundErrors}} | Sort-Object Empfangen_GB -Descending"; Type="PowerShell"; Category="Network-Topology"},
    @{Name="Gateway- und DNS-Konfiguration"; Command="Get-NetIPConfiguration | Where-Object {`$_.IPv4DefaultGateway -or `$_.IPv6DefaultGateway} | Select-Object InterfaceAlias, @{Name='IPv4_Adresse';Expression={(`$_.IPv4Address | Select-Object -First 1).IPAddress}}, @{Name='IPv4_Gateway';Expression={(`$_.IPv4DefaultGateway | Select-Object -First 1).NextHop}}, @{Name='DNS_Server';Expression={`$_.DNSServer.ServerAddresses -join '; '}}, @{Name='DHCP_Aktiviert';Expression={`$_.NetProfile.NetworkCategory}} | Sort-Object InterfaceAlias"; Type="PowerShell"; Category="Network-Topology"},
    @{Name="Netzwerk-Troubleshooting-Infos"; Command="`$networkInfo = @(); Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object { `$adapter = `$_; `$tcpStats = Get-NetTCPConnection | Where-Object { try { (Get-NetAdapter -InterfaceIndex `$_.LocalAddress -ErrorAction SilentlyContinue).InterfaceIndex -eq `$adapter.InterfaceIndex } catch { `$false } }; `$networkInfo += [PSCustomObject]@{ Interface=`$adapter.Name; MAC=`$adapter.MacAddress; Status=`$adapter.Status; LinkSpeed=`$adapter.LinkSpeed; MediaType=`$adapter.MediaType; TCP_Verbindungen=(`$tcpStats | Measure-Object).Count; Typ=if(`$adapter.Virtual){'Virtual'}else{'Physical'} } }; `$networkInfo | Sort-Object Interface"; Type="PowerShell"; Category="Network-Topology"}
)

# Variable fuer die Verbindungsaudit-Ergebnisse
$global:connectionAuditResults = @{}

# Erweiterte Netzwerk-Verbindungsbaum-Analyse-Funktionen
function Get-NetworkConnectionTree {
    Write-DebugLog "Erstelle erweiterten Netzwerk-Verbindungsbaum" "ConnectionAudit"
    
    try {
        # Sammle alle aktiven Verbindungen
        $tcpConnections = Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' }
        $udpConnections = Get-NetUDPEndpoint # Diese Variable wird aktuell nicht weiter verwendet, könnte für zukünftige Erweiterungen sein
        $processes = Get-Process
        
        # Erstelle Verbindungsbaum-Struktur
        $connectionTree = @{
            Timestamp = Get-Date
            ServerInfo = @{
                ComputerName = $env:COMPUTERNAME
                Domain = $env:USERDNSDOMAIN
                User = $env:USERNAME
                OS = (Get-CimInstance Win32_OperatingSystem).Caption
            }
            NetworkTopology = @{}
            ActiveConnections = @()
            ProcessMapping = @{} # Diese Struktur wird gefüllt, aber nicht explizit im Rückgabewert verwendet, könnte implizit durch $processInfo sein
            ExternalConnections = @()
            SecurityAnalysis = @{} # Diese Struktur wird initialisiert, aber nicht gefüllt
        }
        
        # Netzwerk-Topologie analysieren
        $adapters = Get-NetAdapter | Where-Object Status -eq 'Up'
        foreach ($adapter in $adapters) {
            $ipConfig = Get-NetIPConfiguration -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
            if ($ipConfig) {
                $connectionTree.NetworkTopology[$adapter.Name] = @{
                    MAC = $adapter.MacAddress
                    IP = ($ipConfig.IPv4Address | Select-Object -First 1).IPAddress
                    Gateway = ($ipConfig.IPv4DefaultGateway | Select-Object -First 1).NextHop
                    DNS = $ipConfig.DNSServer.ServerAddresses -join ', '
                    Speed = $adapter.LinkSpeed
                    Type = if ($adapter.Virtual) { "Virtual" } else { "Physical" }
                }
            }
        }
        
        # Prozess-Mapping erstellen
        foreach ($connection in $tcpConnections) {
            $process = $processes | Where-Object Id -eq $connection.OwningProcess | Select-Object -First 1
            $processInfo = if ($process) {
                @{
                    Name = $process.ProcessName
                    Path = $(try { $process.MainModule.FileName } catch { "N/A" })
                    StartTime = $process.StartTime
                    Company = $(try { $process.Company } catch { "N/A" })
                }
            } else {
                @{ Name = "Unknown"; Path = "N/A"; StartTime = "N/A"; Company = "N/A" }
            }
            
            $connectionInfo = @{
                LocalAddress = $connection.LocalAddress
                LocalPort = $connection.LocalPort
                RemoteAddress = $connection.RemoteAddress
                RemotePort = $connection.RemotePort
                State = $connection.State
                ProcessInfo = $processInfo
                IsExternal = $connection.RemoteAddress -notmatch '^127\.|^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^::1|^fe80:'
            }
            
            $connectionTree.ActiveConnections += $connectionInfo
            
            # Externe Verbindungen separat sammeln
            if ($connectionInfo.IsExternal -and $connection.RemoteAddress -ne '0.0.0.0' -and $connection.RemoteAddress -ne '::') { # Zusätzliche Prüfung für IPv6 unspecified
                $connectionTree.ExternalConnections += $connectionInfo
            }
        }
        
        return $connectionTree
    }
    catch {
        Write-DebugLog "FEHLER beim Erstellen des Verbindungsbaums: $($_.Exception.Message) $($_.ScriptStackTrace)" "ConnectionAudit"
        return $null
    }
}

function Format-ConnectionTreeHTML {
    param(
        [hashtable]$ConnectionTree,
        [hashtable]$Results
    )
    
    if (-not $ConnectionTree) {
        return "<p>Verbindungsbaum konnte nicht erstellt werden.</p>"
    }
    
    $html = @"
<div class="connection-tree-container">
    <h2>🌐 Netzwerk-Verbindungsbaum - $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')</h2>
    
    <div class="server-summary">
        <h3>📊 Server-Übersicht</h3>
        <div class="info-grid">
            <div class="info-item"><strong>Server:</strong> $($ConnectionTree.ServerInfo.ComputerName)</div>
            <div class="info-item"><strong>Domäne:</strong> $($ConnectionTree.ServerInfo.Domain)</div>
            <div class="info-item"><strong>Benutzer:</strong> $($ConnectionTree.ServerInfo.User)</div>
            <div class="info-item"><strong>OS:</strong> $($ConnectionTree.ServerInfo.OS)</div>
        </div>
    </div>
    
    <div class="network-topology">
        <h3>🔗 Netzwerk-Topologie</h3>
        <table class="styled-table">
            <thead>
                <tr><th>Interface</th><th>IP-Adresse</th><th>Gateway</th><th>DNS</th><th>Typ</th><th>Geschwindigkeit</th></tr>
            </thead>
            <tbody>
"@
    
    foreach ($interface in $ConnectionTree.NetworkTopology.Keys) {
        $topo = $ConnectionTree.NetworkTopology[$interface]
        $html += @"
                <tr>
                    <td>$interface</td>
                    <td>$($topo.IP)</td>
                    <td>$($topo.Gateway)</td>
                    <td>$($topo.DNS)</td>
                    <td>$($topo.Type)</td>
                    <td>$($topo.Speed)</td>
                </tr>
"@
    }
    
    $html += @"
            </tbody>
        </table>
    </div>
    
    <div class="active-connections">
        <h3>⚡ Aktive Verbindungen ($(($ConnectionTree.ActiveConnections | Measure-Object).Count))</h3>
        <table class="styled-table">
            <thead>
                <tr><th>Prozess</th><th>Lokal</th><th>Remote</th><th>Status</th><th>Typ</th><th>Firma</th></tr>
            </thead>
            <tbody>
"@
    
    foreach ($conn in ($ConnectionTree.ActiveConnections | Sort-Object { $_.ProcessInfo.Name })) {
        $connectionType = if ($conn.IsExternal) { "🌍 Extern" } else { "🏠 Lokal" }
        $html += @"
                <tr class="$(if ($conn.IsExternal) { 'external-connection' } else { 'local-connection' })">
                    <td><strong>$($conn.ProcessInfo.Name)</strong></td>
                    <td>$($conn.LocalAddress):$($conn.LocalPort)</td>
                    <td>$($conn.RemoteAddress):$($conn.RemotePort)</td>
                    <td>$($conn.State)</td>
                    <td>$connectionType</td>
                    <td>$($conn.ProcessInfo.Company)</td>
                </tr>
"@
    }
    
    $html += @"
            </tbody>
        </table>
    </div>
    
    <div class="external-analysis">
        <h3>🌍 Externe Verbindungen - Sicherheitsanalyse</h3>
        <p><strong>Anzahl externer Verbindungen:</strong> $(($ConnectionTree.ExternalConnections | Measure-Object).Count)</p>
        <table class="styled-table">
            <thead>
                <tr><th>Remote-IP</th><th>Port</th><th>Prozess</th><th>Pfad</th><th>Bewertung</th></tr>
            </thead>
            <tbody>
"@
    
    foreach ($extConn in ($ConnectionTree.ExternalConnections | Sort-Object RemoteAddress)) {
        $risk = "✅ Normal"
        if ($extConn.ProcessInfo.Path -notmatch "Windows|Program Files") {
            $risk = "⚠️ Prüfen"
        }
        if ($extConn.RemoteAddress -match "^(185\.243\.|91\.234\.|77\.83\.)") {
            $risk = "🚨 Verdächtig"
        }
        
        $html += @"
                <tr class="$(if ($risk -eq '🚨 Verdächtig') { 'suspicious-connection' } elseif ($risk -eq '⚠️ Prüfen') { 'warning-connection' } else { 'normal-connection' })">
                    <td>$($extConn.RemoteAddress)</td>
                    <td>$($extConn.RemotePort)</td>
                    <td>$($extConn.ProcessInfo.Name)</td>
                    <td>$($extConn.ProcessInfo.Path)</td>
                    <td>$risk</td>
                </tr>
"@
    }
    
    $html += @"
            </tbody>
        </table>
    </div>
</div>

<style>
.connection-tree-container { margin: 20px 0; }
.server-summary { background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 15px 0; }
.info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 10px; }
.info-item { padding: 8px; background: white; border-radius: 4px; border-left: 4px solid #FD7E14; }
.network-topology, .active-connections, .external-analysis { margin: 20px 0; }
.styled-table { width: 100%; border-collapse: collapse; margin: 10px 0; }
.styled-table th { background: #FD7E14; color: white; padding: 12px; text-align: left; }
.styled-table td { padding: 10px; border-bottom: 1px solid #ddd; }
.external-connection { background-color: #fff3cd; }
.local-connection { background-color: #f8f9fa; }
.suspicious-connection { background-color: #f8d7da; }
.warning-connection { background-color: #fff3cd; }
.normal-connection { background-color: #d1f7d1; }
.styled-table tr:hover { background-color: #f5f5f5; }
</style>
"@
    
    return $html
}

# Funktion zum Ausfuehren von PowerShell-Befehlen
function Invoke-PSCommand {
    param(
        [string]$Command
    )
    try {
        Write-DebugLog "Ausfuehren von PowerShell-Befehl: $Command" "CommandExec"
        
        # Spezielle Behandlung fuer bestimmte Befehle
        if ($Command -like "*Get-ComputerInfo*") {
            $result = Get-ComputerInfo | Format-List | Out-String
        } else {
            $result = Invoke-Expression -Command $Command | Format-Table -AutoSize | Out-String
        }
        
        Write-DebugLog "PowerShell-Befehl erfolgreich ausgefuehrt. Ergebnis-Laenge: $($result.Length)" "CommandExec"
        return $result
    }
    catch {
        $errorMsg = "Fehler bei der Ausfuehrung des Befehls: $Command`r`n$($_.Exception.Message)"
        Write-DebugLog "FEHLER: $errorMsg" "CommandExec"
        return $errorMsg
    }
}

# Funktion zum Ausfuehren von CMD-Befehlen
function Invoke-CMDCommand {
    param(
        [string]$Command
    )
    try {
        Write-DebugLog "Ausfuehren von CMD-Befehl: $Command" "CommandExec"
        $result = cmd /c $Command 2>&1 | Out-String
        Write-DebugLog "CMD-Befehl erfolgreich ausgefuehrt. Ergebnis-Laenge: $($result.Length)" "CommandExec"
        return $result
    }
    catch {
        $errorMsg = "Fehler bei der Ausfuehrung des Befehls: $Command`r`n$($_.Exception.Message)"
        Write-DebugLog "FEHLER: $errorMsg" "CommandExec"
        return $errorMsg
    }
}

# Funktion zum Pruefen, ob eine bestimmte Serverrolle installiert ist
function Test-ServerRole {
    param(
        [string]$FeatureName
    )
    
    try {
        Write-DebugLog "Pruefe Serverrolle: $FeatureName" "RoleCheck"
        $feature = Get-WindowsFeature -Name $FeatureName -ErrorAction SilentlyContinue
        if ($feature -and $feature.Installed) {
            Write-DebugLog "Serverrolle $FeatureName ist installiert" "RoleCheck"
            return $true
        }
        Write-DebugLog "Serverrolle $FeatureName ist NICHT installiert" "RoleCheck"
        return $false
    }
    catch {
        Write-DebugLog "FEHLER beim Pruefen der Serverrolle $FeatureName - $($_.Exception.Message)" "RoleCheck"
        return $false
    }
}
# VERBINDUNGSAUDIT FUNKTIONEN

# Hauptfunktion fuer die Verbindungsaudit-Durchfuehrung
function Start-ConnectionAuditProcess {
    # UI vorbereiten
    $btnRunConnectionAudit.IsEnabled = $false
    $btnExportConnectionHTML.IsEnabled = $false
    $btnExportConnectionDrawIO.IsEnabled = $false
    $btnCopyConnectionToClipboard.IsEnabled = $false
    $cmbConnectionCategories.IsEnabled = $false
    
    $rtbConnectionResults.Document = New-Object System.Windows.Documents.FlowDocument
    $progressBarConnection.Value = 0
    $txtStatus.Text = "Status: Verbindungsaudit laeuft..."
    
    # UI initial aktualisieren
    $window.Dispatcher.Invoke([Action]{
        $txtProgressConnection.Text = "Initialisiere Verbindungsaudit..."
        $progressBarConnection.Value = 0
    }, "Normal")
    
    # UI refresh erzwingen
    $window.Dispatcher.Invoke([Action]{}, "ApplicationIdle")
    Start-Sleep -Milliseconds 300
    
    # Sammle ausgewaehlte Befehle
    $selectedCommands = @()
    foreach ($cmd in $connectionAuditCommands) {
        if ($connectionCheckboxes[$cmd.Name].IsChecked) {
            $selectedCommands += $cmd
        }
    }
    
    Write-DebugLog "Starte Verbindungsaudit mit $($selectedCommands.Count) ausgewaehlten Befehlen" "ConnectionAudit"
    
    $global:connectionAuditResults = @{}
    $progressStep = 100.0 / $selectedCommands.Count
    $currentProgress = 0
    
    # UI Update mit Anzahl der Befehle
    $window.Dispatcher.Invoke([Action]{
        $txtProgressConnection.Text = "Bereite $($selectedCommands.Count) Verbindungsaudit-Befehle vor..."
    }, "Normal")
    
    # UI refresh erzwingen
    $window.Dispatcher.Invoke([Action]{}, "ApplicationIdle")
    Start-Sleep -Milliseconds 500
    
    for ($i = 0; $i -lt $selectedCommands.Count; $i++) {
        $cmd = $selectedCommands[$i]
        
        # UI aktualisieren - BEGINN des Befehls
        $window.Dispatcher.Invoke([Action]{
            $txtProgressConnection.Text = "Verarbeite: $($cmd.Name) ($($i+1)/$($selectedCommands.Count))"
            $progressBarConnection.Value = $currentProgress
        }, "Normal")
        
        # UI refresh erzwingen
        $window.Dispatcher.Invoke([Action]{}, "ApplicationIdle")
        [System.Windows.Forms.Application]::DoEvents()
        Start-Sleep -Milliseconds 200
        
        Write-DebugLog "Fuehre Verbindungsaudit aus ($($i+1)/$($selectedCommands.Count)): $($cmd.Name)" "ConnectionAudit"
        
        try {
            if ($cmd.Type -eq "PowerShell") {
                $result = Invoke-PSCommand -Command $cmd.Command
            } else {
                $result = Invoke-CMDCommand -Command $cmd.Command
            }
            
            $global:connectionAuditResults[$cmd.Name] = $result
            
            # Erfolg und Fortschrittsbalken aktualisieren
            $currentProgress += $progressStep
            $window.Dispatcher.Invoke([Action]{
                $progressBarConnection.Value = $currentProgress
                $txtProgressConnection.Text = "Abgeschlossen: $($cmd.Name) ($($i+1)/$($selectedCommands.Count))"
            }, "Normal")
            
        } catch {
            $errorMsg = "Fehler: $($_.Exception.Message)"
            $global:connectionAuditResults[$cmd.Name] = $errorMsg
            
            # Fehler und Fortschrittsbalken trotzdem aktualisieren
            $currentProgress += $progressStep
            $window.Dispatcher.Invoke([Action]{
                $progressBarConnection.Value = $currentProgress
                $txtProgressConnection.Text = "Fehler bei: $($cmd.Name) ($($i+1)/$($selectedCommands.Count))"
            }, "Normal")
            
            Write-DebugLog "FEHLER bei Verbindungsaudit $($cmd.Name): $($_.Exception.Message)" "ConnectionAudit"
        }
        
        # UI refresh nach jedem Befehl erzwingen
        $window.Dispatcher.Invoke([Action]{}, "ApplicationIdle")
        [System.Windows.Forms.Application]::DoEvents()
        Start-Sleep -Milliseconds 300
        
        # Zwischenstand der Ergebnisse aktualisieren
        if (($i + 1) % 3 -eq 0 -or $i -eq ($selectedCommands.Count - 1)) {
            $window.Dispatcher.Invoke([Action]{
                try {
                    Update-ConnectionResultsCategories
                    if ($cmbConnectionCategories.SelectedItem) {
                        $selectedCategory = $cmbConnectionCategories.SelectedItem.Tag
                        Show-ConnectionCategoryResults -Category $selectedCategory
                    } else {
                        Show-ConnectionCategoryResults -Category "Alle"
                    }
                }
                catch {
                    Write-DebugLog "FEHLER beim Zwischenupdate der Verbindungsaudit-Ergebnisanzeige: $($_.Exception.Message)" "ConnectionAudit"
                }
            }, "Normal")
            $window.Dispatcher.Invoke([Action]{}, "ApplicationIdle")
            [System.Windows.Forms.Application]::DoEvents()
        }
    }
    
    # Verbindungsaudit abgeschlossen - Finale Updates
    $window.Dispatcher.Invoke([Action]{
        $progressBarConnection.Value = 100
        $txtProgressConnection.Text = "Verbindungsaudit vollstaendig abgeschlossen! $($selectedCommands.Count) Befehle ausgefuehrt."
        
        try {
            # Aktualisiere die Kategorien-Anzeige
            Update-ConnectionResultsCategories
            Show-ConnectionCategoryResults -Category "Alle"
        }
        catch {
            Write-DebugLog "FEHLER beim finalen Update der Verbindungsaudit-Ergebnisanzeige: $($_.Exception.Message)" "ConnectionAudit"
            try {
                Show-SimpleConnectionResults -Category "Alle"
            }
            catch {
                Write-DebugLog "FEHLER auch bei einfacher Verbindungsaudit-Anzeige: $($_.Exception.Message)" "ConnectionAudit"
            }
        }
        
        $txtStatus.Text = "Status: Verbindungsaudit abgeschlossen - $($global:connectionAuditResults.Count) Ergebnisse"
        
        # Buttons wieder aktivieren
        $btnRunConnectionAudit.IsEnabled = $true
        $btnExportConnectionHTML.IsEnabled = $true
        $btnExportConnectionDrawIO.IsEnabled = $true
        $btnCopyConnectionToClipboard.IsEnabled = $true
        $cmbConnectionCategories.IsEnabled = $true
    }, "Normal")
    
    # Finaler UI refresh
    $window.Dispatcher.Invoke([Action]{}, "ApplicationIdle")
    [System.Windows.Forms.Application]::DoEvents()
    
    Write-DebugLog "Verbindungsaudit abgeschlossen mit $($global:connectionAuditResults.Count) Ergebnissen" "ConnectionAudit"
}

# Funktion zum Aktualisieren der Verbindungsaudit-Kategorien-ComboBox
function Update-ConnectionResultsCategories {
    Write-DebugLog "Aktualisiere Verbindungsaudit-Kategorien-ComboBox" "UI"
    
    $cmbConnectionCategories.Items.Clear()
    
    # "Alle" Option hinzufügen
    $allItem = New-Object System.Windows.Controls.ComboBoxItem
    $allItem.Content = "Alle Kategorien"
    $allItem.Tag = "Alle"
    $cmbConnectionCategories.Items.Add($allItem)
    
    # Einzelne Kategorien hinzufügen
    $categories = @{}
    if ($null -ne $connectionAuditCommands) {
        foreach ($cmd in $connectionAuditCommands) {
            $category = if ($cmd.Category) { $cmd.Category } else { "Allgemein" }
            if (-not $categories.ContainsKey($category)) {
                $categories[$category] = 0
            }
            if ($global:connectionAuditResults.ContainsKey($cmd.Name)) {
                $categories[$category]++
            }
        }
    }
    
    foreach ($category in $categories.Keys | Sort-Object) {
        if ($categories[$category] -gt 0) {
            $categoryItem = New-Object System.Windows.Controls.ComboBoxItem
            $categoryItem.Content = "$category ($($categories[$category]))"
            $categoryItem.Tag = $category
            $cmbConnectionCategories.Items.Add($categoryItem)
        }
    }
    
    # Ersten Eintrag auswählen
    if ($cmbConnectionCategories.Items.Count -gt 0) {
        $cmbConnectionCategories.SelectedIndex = 0
    }
}

# Funktion zum Anzeigen der Verbindungsaudit-Ergebnisse
function Show-ConnectionCategoryResults {
    param([string]$Category = "Alle")
    
    Write-DebugLog "Zeige Verbindungsaudit-Ergebnisse fuer Kategorie: $Category" "UI"
    
    if ($global:connectionAuditResults.Count -eq 0) {
        $rtbConnectionResults.Document = New-Object System.Windows.Documents.FlowDocument
        $emptyParagraph = New-Object System.Windows.Documents.Paragraph
        $emptyRun = New-Object System.Windows.Documents.Run("Keine Verbindungsaudit-Ergebnisse verfügbar. Führen Sie zuerst ein Verbindungsaudit durch.")
        $emptyRun.FontStyle = "Italic"
        $emptyRun.Foreground = New-Object System.Windows.Media.SolidColorBrush([System.Windows.Media.Color]::FromRgb(108, 117, 125))
        $emptyParagraph.Inlines.Add($emptyRun)
        $rtbConnectionResults.Document.Blocks.Add($emptyParagraph)
        return
    }
    
    try {
        # Versuche die formatierte Anzeige
        $document = Format-ConnectionRichTextResults -Results $global:connectionAuditResults -CategoryFilter $Category
        $rtbConnectionResults.Document = $document
        
        # Erzwinge Layout-Update
        $rtbConnectionResults.UpdateLayout()
        
        Write-DebugLog "Verbindungsaudit-Ergebnisse erfolgreich formatiert und angezeigt" "UI"
    }
    catch {
        Write-DebugLog "FEHLER bei der formatierten Verbindungsaudit-Anzeige: $($_.Exception.Message) - Verwende Fallback" "UI"
        
        # Fallback: Verwende einfache Textanzeige
        Show-SimpleConnectionResults -Category $Category
    }
}

# Funktion zum Formatieren der Verbindungsaudit-RichTextBox
function Format-ConnectionRichTextResults {
    param(
        [hashtable]$Results,
        [string]$CategoryFilter = "Alle"
    )
    
    Write-DebugLog "Formatiere Verbindungsaudit-Ergebnisse fuer Kategorie: $CategoryFilter" "UI"
    
    # Erstelle ein neues FlowDocument
    $document = New-Object System.Windows.Documents.FlowDocument
    $document.FontFamily = New-Object System.Windows.Media.FontFamily("Segoe UI")
    $document.FontSize = 12
    $document.LineHeight = 18
    
    # Optimierte Layout-Einstellungen
    $document.PageWidth = [Double]::NaN
    $document.PageHeight = [Double]::NaN
    $document.ColumnWidth = [Double]::PositiveInfinity
    $document.TextAlignment = "Left"
    $document.PagePadding = New-Object System.Windows.Thickness(0)
    $document.IsOptimalParagraphEnabled = $true
    $document.IsHyphenationEnabled = $false
    
    # Gruppiere Ergebnisse nach Kategorien
    $categorizedResults = @{}
    foreach ($cmd in $connectionAuditCommands) {
        $category = if ($cmd.Category) { $cmd.Category } else { "Allgemein" }
        if (-not $categorizedResults.ContainsKey($category)) {
            $categorizedResults[$category] = @()
        }
        if ($Results.ContainsKey($cmd.Name)) {
            $categorizedResults[$category] += @{
                Name = $cmd.Name
                Result = $Results[$cmd.Name]
                Command = $cmd
            }
        }
    }
    
    # Bestimme welche Kategorien angezeigt werden sollen
    $categoriesToShow = if ($CategoryFilter -eq "Alle") { 
        $categorizedResults.Keys | Sort-Object 
    } else { 
        @($CategoryFilter) 
    }
    
    $totalItems = 0
    foreach ($category in $categoriesToShow) {
        if ($categorizedResults.ContainsKey($category)) {
            $categoryData = $categorizedResults[$category]
            $totalItems += $categoryData.Count
            
            # Kategorie-Header
            $categoryParagraph = New-Object System.Windows.Documents.Paragraph
            $categoryRun = New-Object System.Windows.Documents.Run("Kategorie: $category")
            $categoryRun.FontWeight = "Bold"
            $categoryRun.FontSize = 16
            $categoryRun.Foreground = New-Object System.Windows.Media.SolidColorBrush([System.Windows.Media.Color]::FromRgb(253, 126, 20)) # Orange für Verbindungsaudit
            $categoryParagraph.Inlines.Add($categoryRun)
            $categoryParagraph.Margin = New-Object System.Windows.Thickness(0, 15, 0, 10)
            $categoryParagraph.TextAlignment = "Left"
            $categoryParagraph.KeepTogether = $true
            $document.Blocks.Add($categoryParagraph)
            
            # Items in dieser Kategorie
            foreach ($item in $categoryData) {
                # Item-Header
                $itemParagraph = New-Object System.Windows.Documents.Paragraph
                $itemRun = New-Object System.Windows.Documents.Run("Eintrag: $($item.Name)")
                $itemRun.FontWeight = "SemiBold"
                $itemRun.FontSize = 13
                $itemRun.Foreground = New-Object System.Windows.Media.SolidColorBrush([System.Windows.Media.Color]::FromRgb(44, 62, 80))
                $itemParagraph.Inlines.Add($itemRun)
                $itemParagraph.Margin = New-Object System.Windows.Thickness(0, 10, 0, 5)
                $itemParagraph.TextAlignment = "Left"
                $itemParagraph.KeepTogether = $true
                $document.Blocks.Add($itemParagraph)
                
                # Kommando-Info (optional)
                if ($item.Command.Command) {
                    $cmdParagraph = New-Object System.Windows.Documents.Paragraph
                    $cmdRun = New-Object System.Windows.Documents.Run("Befehl: $($item.Command.Command)")
                    $cmdRun.FontStyle = "Italic"
                    $cmdRun.FontSize = 10
                    $cmdRun.Foreground = New-Object System.Windows.Media.SolidColorBrush([System.Windows.Media.Color]::FromRgb(108, 117, 125))
                    $cmdParagraph.Inlines.Add($cmdRun)
                    $cmdParagraph.Margin = New-Object System.Windows.Thickness(20, 0, 0, 5)
                    $cmdParagraph.TextAlignment = "Left"
                    $document.Blocks.Add($cmdParagraph)
                }
                
                # Ergebnis in einem optimierten Paragraph
                $resultParagraph = New-Object System.Windows.Documents.Paragraph
                $resultParagraph.Margin = New-Object System.Windows.Thickness(0, 0, 0, 15)
                $resultParagraph.Padding = New-Object System.Windows.Thickness(15)
                $resultParagraph.Background = New-Object System.Windows.Media.SolidColorBrush([System.Windows.Media.Color]::FromRgb(255, 248, 220)) # Heller Orange-Hintergrund
                $resultParagraph.BorderBrush = New-Object System.Windows.Media.SolidColorBrush([System.Windows.Media.Color]::FromRgb(253, 126, 20))
                $resultParagraph.BorderThickness = New-Object System.Windows.Thickness(1)
                $resultParagraph.TextAlignment = "Left"
                
                # Textbehandlung
                $resultText = $item.Result
                if ([string]::IsNullOrWhiteSpace($resultText)) {
                    $resultText = "Keine Daten verfügbar"
                }
                
                $resultRun = New-Object System.Windows.Documents.Run($resultText)
                $resultRun.FontFamily = New-Object System.Windows.Media.FontFamily("Consolas")
                $resultRun.FontSize = 11
                $resultParagraph.Inlines.Add($resultRun)
                
                $document.Blocks.Add($resultParagraph)
            }
        }
    }
    
    return $document
}

# Fallback-Funktion für einfache Verbindungsaudit-Textanzeige
function Show-SimpleConnectionResults {
    param([string]$Category = "Alle")
    
    Write-DebugLog "Verwende einfache Textanzeige für Verbindungsaudit-Kategorie: $Category" "UI"
    
    # Erstelle einfaches FlowDocument
    $document = New-Object System.Windows.Documents.FlowDocument
    $document.FontFamily = New-Object System.Windows.Media.FontFamily("Consolas")
    $document.FontSize = 11
    $document.PageWidth = [Double]::NaN
    $document.PageHeight = [Double]::NaN
    $document.ColumnWidth = [Double]::PositiveInfinity
    
    # Sammle alle relevanten Ergebnisse als einfachen Text
    $resultText = ""
    
    # Gruppiere nach Kategorien
    $categorizedResults = @{}
    foreach ($cmd in $connectionAuditCommands) {
        $cmdCategory = if ($cmd.Category) { $cmd.Category } else { "Allgemein" }
        if (-not $categorizedResults.ContainsKey($cmdCategory)) {
            $categorizedResults[$cmdCategory] = @()
        }
        if ($global:connectionAuditResults.ContainsKey($cmd.Name)) {
            $categorizedResults[$cmdCategory] += @{
                Name = $cmd.Name
                Result = $global:connectionAuditResults[$cmd.Name]
            }
        }
    }
    
    # Bestimme anzuzeigende Kategorien
    $categoriesToShow = if ($Category -eq "Alle") { 
        $categorizedResults.Keys | Sort-Object 
    } else { 
        @($Category) 
    }
    
    $totalItems = 0
    foreach ($cat in $categoriesToShow) {
        if ($categorizedResults.ContainsKey($cat)) {
            $categoryData = $categorizedResults[$cat]
            $totalItems += $categoryData.Count
            
            $resultText += "`n" + "="*60 + "`n"
            $resultText += "VERBINDUNGSAUDIT KATEGORIE: $cat`n"
            $resultText += "="*60 + "`n`n"
            
            foreach ($item in $categoryData) {
                $resultText += "-"*40 + "`n"
                $resultText += "EINTRAG: $($item.Name)`n"
                $resultText += "-"*40 + "`n"
                $resultText += "$($item.Result)`n`n"
            }
        }
    }
    
    # Erstelle einfachen Paragraph mit dem gesamten Text
    $paragraph = New-Object System.Windows.Documents.Paragraph
    $run = New-Object System.Windows.Documents.Run($resultText)
    $paragraph.Inlines.Add($run)
    $document.Blocks.Add($paragraph)
    
    $rtbConnectionResults.Document = $document
}

# Funktion zum Anzeigen der Verbindungsaudit-Ergebnisse mit Kategorisierung und WPF-Formatierung
function Show-ConnectionResults {
    param(
        [string]$Category = "Alle"
    )

    Write-DebugLog "Zeige Verbindungsergebnisse für Kategorie: $Category" "UI"

    # RichTextBox vorbereiten
    $rtbConnectionResults.Document.Blocks.Clear()
    $rtbConnectionResults.IsEnabled = $true # Sicherstellen, dass die RTB aktiviert ist

    # Prüfen, ob überhaupt Ergebnisse vorhanden sind
    if ($null -eq $global:connectionAuditResults -or $global:connectionAuditResults.Count -eq 0) {
        $paragraph = New-Object System.Windows.Documents.Paragraph
        $run = New-Object System.Windows.Documents.Run("Keine Verbindungsaudit-Ergebnisse vorhanden.")
        $paragraph.Inlines.Add($run)
        $rtbConnectionResults.Document.Blocks.Add($paragraph)
        Write-DebugLog "Keine Verbindungsaudit-Ergebnisse zum Anzeigen." "UI"
        return
    }

    # Prüfen, ob Befehlsdefinitionen für die Kategorisierung vorhanden sind
    if ($null -eq $connectionAuditCommands -or $connectionAuditCommands.Count -eq 0) {
        Write-DebugLog "Show-ConnectionResults: Keine Verbindungsaudit-Befehlsdefinitionen vorhanden. Zeige unkategorisierte Rohdaten." "UI-Warning"
        
        # Fallback: Unkategorisierte Rohdaten anzeigen, wenn keine Befehlsdefinitionen geladen sind
        $document = New-Object System.Windows.Documents.FlowDocument
        $document.PagePadding = New-Object System.Windows.Thickness(5)

        $headerParagraph = New-Object System.Windows.Documents.Paragraph
        $headerRun = New-Object System.Windows.Documents.Run("VERBINDUNGSAUDIT ERGEBNISSE (Unkategorisiert)")
        $headerRun.FontWeight = [System.Windows.FontWeights]::Bold
        $headerRun.FontSize = 14
        $headerParagraph.Inlines.Add($headerRun)
        $headerParagraph.Margin = New-Object System.Windows.Thickness(0,0,0,10) # Abstand nach unten
        $document.Blocks.Add($headerParagraph)

        foreach ($key in ($global:connectionAuditResults.Keys | Sort-Object)) {
            $itemNameParagraph = New-Object System.Windows.Documents.Paragraph
            $itemNameRun = New-Object System.Windows.Documents.Run("BEFEHL: $key") # Geändert zu "BEFEHL" für Klarheit
            $itemNameRun.FontWeight = [System.Windows.FontWeights]::SemiBold
            $itemNameParagraph.Inlines.Add($itemNameRun)
            $itemNameParagraph.Margin = New-Object System.Windows.Thickness(0,5,0,2)
            $document.Blocks.Add($itemNameParagraph)

            $itemResultParagraph = New-Object System.Windows.Documents.Paragraph
            $resultDisplayString = if ($null -ne $global:connectionAuditResults[$key]) {
                                       if ($global:connectionAuditResults[$key] -is [string]) { 
                                           $global:connectionAuditResults[$key]
                                       } else { 
                                           ($global:connectionAuditResults[$key] | Out-String).TrimEnd() 
                                       }
                                   } else { 
                                       "[Kein Ergebnis oder NULL]" 
                                   }
            $itemResultRun = New-Object System.Windows.Documents.Run($resultDisplayString)
            $itemResultRun.FontFamily = New-Object System.Windows.Media.FontFamily("Consolas, Courier New, Lucida Console")
            $itemResultRun.FontSize = 11
            $itemResultParagraph.Inlines.Add($itemResultRun)
            $itemResultParagraph.Margin = New-Object System.Windows.Thickness(10,0,0,10) # Einzug links, Abstand unten
            $document.Blocks.Add($itemResultParagraph)
        }
        $rtbConnectionResults.Document = $document
        return
    }

    # Ergebnisse nach Kategorien gruppieren
    $categorizedResults = @{}
    foreach ($cmdDef in $connectionAuditCommands) {
        $cmdCategory = if ([string]::IsNullOrWhiteSpace($cmdDef.Category)) { "Allgemein" } else { $cmdDef.Category }
        
        if (-not $categorizedResults.ContainsKey($cmdCategory)) {
            $categorizedResults[$cmdCategory] = [System.Collections.Generic.List[object]]::new()
        }
        
        if ($global:connectionAuditResults.ContainsKey($cmdDef.Name)) {
            $categorizedResults[$cmdCategory].Add(@{
                Name = $cmdDef.Name
                Result = $global:connectionAuditResults[$cmdDef.Name]
            })
        }
    }

    # Zu anzeigende Kategorien bestimmen
    $categoriesToShow = if ($Category -eq "Alle") { 
        $categorizedResults.Keys | Where-Object { $categorizedResults[$_].Count -gt 0 } | Sort-Object 
    } else { 
        if ($categorizedResults.ContainsKey($Category) -and $categorizedResults[$Category].Count -gt 0) {
            @($Category) 
        } else {
            @() 
        }
    }
    
    $document = New-Object System.Windows.Documents.FlowDocument
    $document.PagePadding = New-Object System.Windows.Thickness(5)

    if ($categoriesToShow.Count -eq 0) {
        $message = if ($Category -eq "Alle") {
            "Keine kategorisierten Ergebnisse gefunden. Möglicherweise sind alle Ergebnisse ohne Kategorie oder die Befehlsdefinitionen passen nicht."
        } else {
            "Keine Ergebnisse für Kategorie '$Category' gefunden oder die Kategorie ist leer."
        }
        $paragraph = New-Object System.Windows.Documents.Paragraph
        $run = New-Object System.Windows.Documents.Run($message)
        $paragraph.Inlines.Add($run)
        $document.Blocks.Add($paragraph)
        Write-DebugLog $message "UI"
    } else {
        foreach ($catName in $categoriesToShow) {
            # Erneute Prüfung, obwohl $categoriesToShow bereits gefiltert sein sollte
            if ($categorizedResults.ContainsKey($catName) -and $categorizedResults[$catName].Count -gt 0) {
                $categoryItems = $categorizedResults[$catName]
                
                # Kategorie-Überschrift
                $headerParagraph = New-Object System.Windows.Documents.Paragraph
                $headerRun = New-Object System.Windows.Documents.Run("KATEGORIE: $($catName.ToUpper())")
                $headerRun.FontWeight = [System.Windows.FontWeights]::Bold
                $headerRun.FontSize = 14 
                $headerParagraph.Inlines.Add($headerRun)
                $headerParagraph.Margin = New-Object System.Windows.Thickness(0,10,0,5) # Oben, Rechts, Unten, Links
                $document.Blocks.Add($headerParagraph)

                foreach ($item in $categoryItems) {
                    # Eintragsname (Befehlsname)
                    $itemNameParagraph = New-Object System.Windows.Documents.Paragraph
                    $itemNameRun = New-Object System.Windows.Documents.Run($item.Name)
                    $itemNameRun.FontWeight = [System.Windows.FontWeights]::SemiBold
                    $itemNameRun.FontSize = 12
                    $itemNameParagraph.Inlines.Add($itemNameRun)
                    $itemNameParagraph.Margin = New-Object System.Windows.Thickness(0,5,0,2)
                    $document.Blocks.Add($itemNameParagraph)

                    # Eintragsergebnis
                    $itemResultParagraph = New-Object System.Windows.Documents.Paragraph
                    $resultDisplayString = ""
                    if ($null -ne $item.Result) {
                        if ($item.Result -is [string]) {
                            $resultDisplayString = $item.Result
                        } else {
                            $resultDisplayString = ($item.Result | Out-String).TrimEnd()
                        }
                    } else {
                        $resultDisplayString = "[Kein Ergebnis oder NULL]"
                    }

                    $itemResultRun = New-Object System.Windows.Documents.Run($resultDisplayString)
                    $itemResultRun.FontFamily = New-Object System.Windows.Media.FontFamily("Consolas, Courier New, Lucida Console") 
                    $itemResultRun.FontSize = 11
                    $itemResultParagraph.Inlines.Add($itemResultRun)
                    $itemResultParagraph.Margin = New-Object System.Windows.Thickness(10,0,0,10) # Einzug links, Abstand unten
                    $document.Blocks.Add($itemResultParagraph)
                }
            }
        }
    }
    
    $rtbConnectionResults.Document = $document
    Write-DebugLog "Anzeige der Verbindungsergebnisse für Kategorie '$Category' abgeschlossen." "UI"
}

# Funktion zum sicheren Ausführen von Get-WinEvent Befehlen
function Invoke-SafeWinEvent {
    param(
        [hashtable]$FilterHashtable,
        [int]$MaxEvents = 50,
        [string]$Description = "Events"
    )
    
    try {
        Write-DebugLog "Versuche Get-WinEvent mit Filter: $($FilterHashtable | ConvertTo-Json -Compress)" "SafeWinEvent"
        
        # Versuche Event-Abfrage mit ErrorAction Stop. 2>$null unterdrückt die Standard-Fehlerausgabe in der Konsole.
        $events = Get-WinEvent -FilterHashtable $FilterHashtable -MaxEvents $MaxEvents -ErrorAction Stop 2>$null
        
        # Wenn $events nicht $null ist und Elemente enthält (und keine Exception ausgelöst wurde),
        # werden die Events zurückgegeben.
        if ($null -ne $events -and $events.Count -gt 0) {
            Write-DebugLog "Erfolgreich $($events.Count) Events gefunden" "SafeWinEvent"
            return $events
        } else {
            # Dieser Block wird erreicht, wenn Get-WinEvent $null oder ein leeres Array zurückgibt, 
            # ohne einen Fehler auszulösen, der von ErrorAction Stop abgefangen würde.
            Write-DebugLog "Get-WinEvent lieferte keine Events oder ein leeres Ergebnis (ohne Exception). Filter: $($FilterHashtable | ConvertTo-Json -Compress). Gebe leeres Array zurück." "SafeWinEvent"
            return @() 
        }
    }
    catch { # Fängt alle terminierenden Fehler von Get-WinEvent ab
        $ErrorRecord = $PSItem # $PSItem ist der ErrorRecord im Catch-Block (in PSv3+).
        
        Write-DebugLog "Get-WinEvent Fehler aufgetreten. Message: '$($ErrorRecord.Exception.Message)'. FullyQualifiedErrorId: '$($ErrorRecord.FullyQualifiedErrorId)'." "SafeWinEvent"
        
        # Spezifische Behandlung für häufige Fehler
        # Prüfung auf 'NoMatchingEventsFound' anhand der FullyQualifiedErrorId (bevorzugt)
        if ($ErrorRecord.FullyQualifiedErrorId -eq "NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand") {
            Write-DebugLog "Fehler 'NoMatchingEventsFound' (basierend auf FQID) abgefangen. Gebe leeres Array zurück." "SafeWinEvent"
            return @()
        }
        # Fallback: Prüfung auf 'NoMatchingEventsFound' oder deutschsprachige Entsprechung anhand der Fehlermeldung
        elseif ($ErrorRecord.Exception.Message -like "*NoMatchingEventsFound*" -or $ErrorRecord.Exception.Message -like "*Es wurden keine Ereignisse gefunden*") {
            Write-DebugLog "Fehler '$($ErrorRecord.Exception.Message)' (Nachricht ähnlich 'Keine Events gefunden') abgefangen. Gebe leeres Array zurück." "SafeWinEvent"
            return @()
        }
        # Zugriff verweigert (Access Denied)
        elseif ($ErrorRecord.Exception.Message -like "*Access is denied*" -or $ErrorRecord.Exception.Message -like "*Zugriff verweigert*") {
            Write-DebugLog "Fehler '$($ErrorRecord.Exception.Message)' (Zugriff verweigert) abgefangen." "SafeWinEvent"
            return "$Description nicht verfügbar - Keine Berechtigung für Event-Log-Zugriff"
        }
        # Kanal/Log nicht gefunden (Channel/Log not found)
        elseif (
            $ErrorRecord.Exception.Message -like "*The specified channel could not be found*" -or 
            $ErrorRecord.Exception.Message -like "*Der angegebene Kanal wurde nicht gefunden*" -or
            $ErrorRecord.Exception.Message -like "*log does not exist*" -or # Allgemeinere Prüfung auf Nichtexistenz des Logs
            $ErrorRecord.Exception.Message -like "*existiert nicht*" # Deutsche Variante für "existiert nicht"
        ) {
            Write-DebugLog "Fehler '$($ErrorRecord.Exception.Message)' (Kanal/Log existiert nicht) abgefangen." "SafeWinEvent"
            return "$Description nicht verfügbar - Event-Log-Kanal existiert nicht"
        }
        # Andere Fehler
        else {
            # Versuche, eine kurze, prägnante Fehlermeldung zu extrahieren (erster Satz oder erste Zeile)
            $shortErrorMessage = "Unbekannter Fehler" # Standardwert
            if ($ErrorRecord.Exception.Message) {
                $splitMessages = $ErrorRecord.Exception.Message -split '\r?\n|\. '
                if ($splitMessages.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($splitMessages[0])) {
                    $shortErrorMessage = $splitMessages[0]
                }
            }
            Write-DebugLog "Allgemeiner Get-WinEvent Fehler: '$shortErrorMessage'. Vollständige Exception: $($ErrorRecord.Exception)" "SafeWinEvent"
            return "$Description nicht verfügbar - Event-Log-Fehler: $shortErrorMessage"
        }
    }
}

# Funktion zum HTML-Export der Verbindungsaudit-Ergebnisse
function Export-ConnectionAuditToHTML {
    param(
        [hashtable]$Results,
        [string]$FilePath
    )
    
    Write-DebugLog "Starte Verbindungsaudit HTML-Export nach: $FilePath" "Export"

    # Helper to replace Umlaute and escape HTML
    function Convert-ToDisplayString {
        param([string]$Text)
        if ([string]::IsNullOrEmpty($Text)) { return "" }
        $processedText = $Text -replace 'ä', 'ae' -replace 'ö', 'oe' -replace 'ü', 'ue' -replace 'Ä', 'Ae' -replace 'Ö', 'Oe' -replace 'Ü', 'Ue' -replace 'ß', 'ss'
        return [System.Security.SecurityElement]::Escape($processedText)
    }
    
    # Erweiterte Serverinformationen sammeln
    $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cpuInfoObj = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    $totalRamBytes = (Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue | Measure-Object -Property Capacity -Sum).Sum
    
    $serverInfo = @{
        ServerName = $env:COMPUTERNAME
        ReportDate = Get-Date -Format "dd.MM.yyyy | HH:mm:ss"
        Domain = $env:USERDOMAIN
        User = $env:USERNAME
        OS = if ($osInfo) { "$($osInfo.Caption) $($osInfo.OSArchitecture)" } else { "N/A" }
        CPU = if ($cpuInfoObj) { $cpuInfoObj.Name } else { "N/A" }
        RAM = if ($totalRamBytes) { "{0:N2} GB" -f ($totalRamBytes / 1GB) } else { "N/A" }
    }

    # Gruppiere Ergebnisse nach Kategorien
    $groupedResults = @{}
    
    if ($null -ne $connectionAuditCommands) {
        foreach ($cmdDef in $connectionAuditCommands) {
            $categoryName = if ($cmdDef.Category) { $cmdDef.Category } else { "Allgemein" }
            
            if ($Results.ContainsKey($cmdDef.Name)) {
                if (-not $groupedResults.ContainsKey($categoryName)) {
                    $groupedResults[$categoryName] = @()
                }
                
                $groupedResults[$categoryName] += @{
                    Name = $cmdDef.Name
                    Result = $Results[$cmdDef.Name]
                    Command = $cmdDef
                }
            }
        }
    }

    # Navigationselemente und Tab-Inhalte generieren
    $sidebarNavLinks = ""
    $mainContentTabs = ""
    $firstTabId = $null
    
    $sortedCategories = $groupedResults.Keys | Sort-Object
    
    foreach ($categoryKey in $sortedCategories) {
        $items = $groupedResults[$categoryKey]
        $displayCategory = Convert-ToDisplayString $categoryKey
        
        $categoryIdPart = $categoryKey -replace '[^a-zA-Z0-9_]', ''
        if ($categoryIdPart.Length -eq 0) { 
            $categoryIdPart = "cat" + ($categoryKey.GetHashCode() | ForEach-Object ToString X) 
        }
        $tabId = "tab_$categoryIdPart"

        if ($null -eq $firstTabId) { $firstTabId = $tabId }

        $sidebarNavLinks += @"
<li class="nav-item category-nav">
    <a href="#" class="nav-link" onclick="showTab('$tabId', this)">
        $displayCategory ($($items.Count))
    </a>
</li>
"@
        
        $tabContent = "<div id='$tabId' class='tab-content'>"
        $tabContent += "<h2 class='content-category-title'>$displayCategory</h2>"

        foreach ($item in $items) {
            $displayItemName = Convert-ToDisplayString $item.Name
            $displayResult = Convert-ToDisplayString $item.Result
            
            $tabContent += @"
<div class="section">
    <div class="section-header">
        <h3 class="section-title">$displayItemName</h3>
    </div>
    <div class="section-content">
        <pre>$displayResult</pre>
    </div>
</div>
"@
        }
        
        $tabContent += "</div>"
        $mainContentTabs += $tabContent
    }

    # Erstelle die vollständige HTML-Ausgabe
    $htmlOutput = @"
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verbindungsaudit Bericht - $(Convert-ToDisplayString $serverInfo.ServerName)</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f8f9fa; color: #333; line-height: 1.6; }
        .page-container { max-width: 1400px; margin: 0 auto; background-color: #ffffff; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px 40px; }
        .header-title { font-size: 2.2em; font-weight: 300; margin-bottom: 10px; }
        .header-info-cards-container { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 25px; }
        .info-card { background-color: rgba(255,255,255,0.15); padding: 12px 18px; border-radius: 8px; backdrop-filter: blur(10px); }
        .main-content-wrapper { display: flex; min-height: 70vh; }
        .sidebar { width: 280px; background-color: #f8f9fa; border-right: 1px solid #e0e4e9; padding: 25px 0; }
        .nav-list { list-style: none; }
        .category-nav { margin: 0; }
        .nav-link { display: block; padding: 12px 25px; color: #495057; text-decoration: none; border-left: 4px solid transparent; transition: all 0.3s ease; }
        .nav-link:hover, .nav-link.active { background-color: #e3f2fd; color: #1976d2; border-left-color: #1976d2; }
        .content-area { flex: 1; padding: 25px 35px; overflow-y: auto; background-color: #ffffff; }
        .content-category-title { font-size: 1.6em; color: #005a9e; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #eef1f5; }
        .tab-content { display: none; }
        .tab-content.active { display: block; animation: fadeIn 0.4s ease-in-out; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
        .section { margin-bottom: 30px; background: #ffffff; border-radius: 5px; border: 1px solid #e7eaf0; box-shadow: 0 1px 5px rgba(0,0,0,0.05); overflow: hidden; }
        .section-header { background: #f7f9fc; padding: 12px 18px; border-bottom: 1px solid #e7eaf0; }
        .section-title { font-size: 1.15em; font-weight: 600; color: #2c3e50; margin: 0; }
        .section-content { padding: 18px; }
        pre { background-color: #fdfdff; padding: 12px; border: 1px solid #e0e4e9; border-radius: 4px; white-space: pre-wrap; word-wrap: break-word; font-family: 'Consolas', 'Monaco', 'Courier New', monospace; font-size: 0.85em; line-height: 1.5; overflow-x: auto; color: #333; }
        .footer-timestamp { color: #505050; font-size: 0.8em; text-align: center; padding: 15px 40px; background-color: #e9ecef; border-top: 1px solid #d8dde3; }
        .footer-timestamp a { color: #005a9e; text-decoration: none; }
        .footer-timestamp a:hover { text-decoration: underline; }
    </style>
    <script>
        function showTab(tabId, clickedElement) {
            var i, contents, navLinks;
            contents = document.querySelectorAll('.tab-content');
            for (i = 0; i < contents.length; i++) {
                contents[i].classList.remove('active');
            }
            
            navLinks = document.querySelectorAll('.sidebar .category-nav .nav-link');
            for (i = 0; i < navLinks.length; i++) {
                navLinks[i].classList.remove('active');
            }
            
            var selectedTabContent = document.getElementById(tabId);
            if (selectedTabContent) {
                selectedTabContent.classList.add('active');
            }
            
            if (clickedElement) {
                clickedElement.classList.add('active');
            }
        }
        
        window.onload = function() {
            var firstNavLink = document.querySelector('.sidebar .nav-list .category-nav .nav-link');
            if (firstNavLink) {
                firstNavLink.click(); 
            } else {
                var firstContent = document.querySelector('.tab-content');
                if (firstContent) {
                    firstContent.classList.add('active');
                }
            }
        }
    </script>
</head>
<body>
    <div class="page-container">
        <header class="header">
            <h1 class="header-title">🌐 Verbindungsaudit Bericht</h1>
            <div class="header-info-cards-container">
                <div class="info-card"><strong>Hostname:</strong> $(Convert-ToDisplayString $serverInfo.ServerName)</div>
                <div class="info-card"><strong>Domaene:</strong> $(Convert-ToDisplayString $serverInfo.Domain)</div>
                <div class="info-card"><strong>Betriebssystem:</strong> $(Convert-ToDisplayString $serverInfo.OS)</div>
                <div class="info-card"><strong>CPU:</strong> $(Convert-ToDisplayString $serverInfo.CPU)</div>
                <div class="info-card"><strong>RAM:</strong> $(Convert-ToDisplayString $serverInfo.RAM)</div>
                <div class="info-card"><strong>Berichtsdatum:</strong> $($serverInfo.ReportDate)</div>
                <div class="info-card"><strong>Benutzer:</strong> $(Convert-ToDisplayString $serverInfo.User)</div>
            </div>
        </header>
        
        <div class="main-content-wrapper">
            <nav class="sidebar">
                <ul class="nav-list">
                    $sidebarNavLinks
                </ul>
            </nav>
            <main class="content-area">
                $mainContentTabs
            </main>
        </div>
        
        <footer class="footer-timestamp">
            Verbindungsaudit Bericht erstellt von easyWSAudit am $($serverInfo.ReportDate) | <a href="https://psscripts.de" target="_blank">PSscripts.de</a> | Andreas Hepp
        </footer>
    </div>
</body>
</html>
"@

    $htmlOutput | Out-File -FilePath $FilePath -Encoding utf8
    Write-DebugLog "Verbindungsaudit HTML-Export abgeschlossen" "Export"
}

# Funktion zum Generieren des HTML-Exports
function Export-AuditToHTML {
    param(
        [hashtable]$Results,
        [string]$FilePath
    )
    
    Write-DebugLog "Starte HTML-Export nach: $FilePath" "Export"

    # Helper to replace Umlaute and escape HTML
    function Convert-ToDisplayString {
        param([string]$Text)
        if ([string]::IsNullOrEmpty($Text)) { return "" }
        $processedText = $Text -replace 'ä', 'ae' -replace 'ö', 'oe' -replace 'ü', 'ue' -replace 'Ä', 'Ae' -replace 'Ö', 'Oe' -replace 'Ü', 'Ue' -replace 'ß', 'ss'
        # Weitere Sonderzeichen koennten hier bei Bedarf behandelt werden
        return [System.Security.SecurityElement]::Escape($processedText)
    }
    
    # Erweiterte Serverinformationen sammeln
    $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cpuInfoObj = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    $totalRamBytes = (Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue | Measure-Object -Property Capacity -Sum).Sum
    $driveC = Get-Volume -DriveLetter 'C' -ErrorAction SilentlyContinue
    
    $serverInfo = @{
        ServerName = $env:COMPUTERNAME
        ReportDate = Get-Date -Format "dd.MM.yyyy | HH:mm:ss" # Format beibehalten, da es ein Datum ist
        Domain = $env:USERDOMAIN
        User = $env:USERNAME
        OS = if ($osInfo) { "$($osInfo.Caption) $($osInfo.OSArchitecture)" } else { "N/A" }
        CPU = if ($cpuInfoObj) { $cpuInfoObj.Name } else { "N/A" }
        RAM = if ($totalRamBytes) { "{0:N2} GB" -f ($totalRamBytes / 1GB) } else { "N/A" }
        DiskCTotal = if ($driveC) { "{0:N2} GB" -f ($driveC.Size / 1GB) } else { "N/A" }
        DiskCFree = if ($driveC) { "{0:N2} GB" -f ($driveC.SizeRemaining / 1GB) } else { "N/A" }
    }

    # Gruppiere Ergebnisse nach Kategorien (gleiche Logik wie in der GUI)
    $groupedResults = @{}
    
    # Definiere die gewünschte Reihenfolge der Kategorien (System an erster Stelle)
    $categoryOrder = @(
        "System",
        "Hardware", 
        "Storage",
        "Network",
        "Security",
        "Services",
        "Tasks",
        "Events",
        "Features",
        "Software",
        "Updates",
        "Active-Directory",
        "DNS",
        "DHCP",
        "IIS",
        "WDS",
        "Hyper-V",
        "Cluster",
        "WSUS",
        "FileServices",
        "PrintServices",
        "RDS",
        "PKI",
        "ADFS",
        "ADLDS",
        "ADRMS",
        "DeviceAttestation",
        "VolumeActivation",
        "Backup",
        "NPAS",
        "HGS",
        "RemoteAccess",
        "InternalDB",
        "WindowsDefender",
        "WAS",
        "SearchService",
        "ServerEssentials",
        "Migration",
        "Identity",
        "FileSharing",
        "UserProfiles",
        "Firewall",
        "PowerManagement",
        "CredentialManager",
        "AuditPolicy",
        "GroupPolicy",
        "InstalledSoftware",
        "Environment"
    )
    
    if ($null -ne $commands) {
        foreach ($cmdDef in $commands) {
            # Verwende die Category direkt aus dem Befehl
            $categoryName = if ($cmdDef.Category) { $cmdDef.Category } else { "Allgemein" }
            
            if ($Results.ContainsKey($cmdDef.Name)) {
                if (-not $groupedResults.ContainsKey($categoryName)) {
                    $groupedResults[$categoryName] = @()
                }
                
                $groupedResults[$categoryName] += @{
                    Name = $cmdDef.Name
                    Result = $Results[$cmdDef.Name]
                    Command = $cmdDef
                }
            }
        }
    }

    # Navigationselemente und Tab-Inhalte generieren mit gewünschter Reihenfolge
    $sidebarNavLinks = ""
    $mainContentTabs = ""
    $firstTabId = $null
    
    # Erstelle eine sortierte Liste der Kategorien basierend auf der gewünschten Reihenfolge
    $sortedCategories = @()
    
    # Füge Kategorien in der gewünschten Reihenfolge hinzu
    foreach ($orderCat in $categoryOrder) {
        if ($groupedResults.ContainsKey($orderCat)) {
            $sortedCategories += $orderCat
        }
    }
    
    # Füge alle anderen Kategorien alphabetisch sortiert hinzu
    foreach ($categoryKey in ($groupedResults.Keys | Sort-Object)) {
        if ($categoryKey -notin $sortedCategories) {
            $sortedCategories += $categoryKey
        }
    }
    
    foreach ($categoryKey in $sortedCategories) {
        $items = $groupedResults[$categoryKey]
        $displayCategory = Convert-ToDisplayString $categoryKey
        
        # Spezielle Anzeigenamen für bessere Lesbarkeit
        $displayCategoryName = switch ($categoryKey) {
            "System" { "System-Informationen" }
            "Hardware" { "Hardware-Informationen" }
            "Storage" { "Speicher & Festplatten" }
            "Network" { "Netzwerk-Konfiguration" }
            "Security" { "Sicherheits-Einstellungen" }
            "Services" { "Dienste & Services" }
            "Tasks" { "Geplante Aufgaben" }
            "Events" { "Ereignisprotokoll" }
            "Features" { "Installierte Features" }
            "Software" { "Software & Programme" }
            "Updates" { "Windows Updates" }
            "Active-Directory" { "Active Directory" }
            "DNS" { "DNS-Server" }
            "DHCP" { "DHCP-Server" }
            "IIS" { "Internet Information Services (IIS)" }
            "WDS" { "Windows Deployment Services" }
            "Hyper-V" { "Hyper-V Virtualisierung" }
            "Cluster" { "Failover Clustering" }
            "WSUS" { "Windows Server Update Services" }
            "FileServices" { "Datei-Services" }
            "PrintServices" { "Druck-Services" }
            "RDS" { "Remote Desktop Services" }
            "PKI" { "Zertifikat-Services (PKI)" }
            "ADFS" { "Active Directory Federation Services" }
            "ADLDS" { "AD Lightweight Directory Services" }
            "ADRMS" { "AD Rights Management Services" }
            "DeviceAttestation" { "Device Health Attestation" }
            "VolumeActivation" { "Volume Activation Services" }
            "Backup" { "Windows Server Backup" }
            "NPAS" { "Network Policy and Access Services" }
            "HGS" { "Host Guardian Service" }
            "RemoteAccess" { "Remote Access Services" }
            "InternalDB" { "Windows Internal Database" }
            "WindowsDefender" { "Windows Defender" }
            "WAS" { "Windows Process Activation Service" }
            "SearchService" { "Windows Search Service" }
            "ServerEssentials" { "Windows Server Essentials" }
            "Migration" { "Migration Services" }
            "Identity" { "Windows Identity Foundation" }
            "FileSharing" { "Dateifreigaben" }
            "UserProfiles" { "Benutzer-Profile" }
            "Firewall" { "Windows Firewall" }
            "PowerManagement" { "Energieverwaltung" }
            "CredentialManager" { "Anmeldeinformationsverwaltung" }
            "AuditPolicy" { "Audit-Richtlinien" }
            "GroupPolicy" { "Gruppenrichtlinien" }
            "InstalledSoftware" { "Installierte Software" }
            "Environment" { "Umgebungsvariablen" }
            default { $displayCategory }
        }
        
        $categoryIdPart = $categoryKey -replace '[^a-zA-Z0-9_]', ''
        if ($categoryIdPart.Length -eq 0) { 
            $categoryIdPart = "cat" + ($categoryKey.GetHashCode() | ForEach-Object ToString X) 
        }
        $tabId = "tab_$categoryIdPart"

        if ($null -eq $firstTabId) { $firstTabId = $tabId }

        $sidebarNavLinks += @"
<li class="nav-item category-nav">
    <a href="#" class="nav-link" onclick="showTab('$tabId', this)">
        $displayCategoryName ($($items.Count))
    </a>
</li>
"@
        
        $tabContent = "<div id='$tabId' class='tab-content'>"
        $tabContent += "<h2 class='content-category-title'>$displayCategoryName</h2>"

        foreach ($item in $items) {
            $displayItemName = Convert-ToDisplayString $item.Name
            $displayItemResult = Convert-ToDisplayString $item.Result
            
            # Füge Kommando-Information hinzu, falls verfügbar
            $commandInfo = ""
            if ($item.Command -and $item.Command.Command) {
                $commandInfo = "<p class='command-info'><strong>Befehl:</strong> <code>$(Convert-ToDisplayString $item.Command.Command)</code></p>"
            }
            
            $tabContent += @"
<div class="section">
    <div class="section-header">
        <h3 class="section-title">$displayItemName</h3>
    </div>
    <div class="section-content">
        $commandInfo
        <pre>$displayItemResult</pre>
    </div>
</div>
"@
        }
        $tabContent += "</div>"
        $mainContentTabs += $tabContent
    }

    # HTML-Gesamtstruktur
    $htmlOutput = @"
<!DOCTYPE html>
<html lang="de">
<head>
    <title>$(Convert-ToDisplayString "Windows Server Audit Bericht - $($serverInfo.ServerName)")</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 0; 
            background-color: #f0f2f5; /* Etwas hellerer Hintergrund */
            color: #333;
            line-height: 1.6;
        }
        .page-container {
            display: flex;
            flex-direction: column;
            min-height: 100vh;
        }
        .header {
            background: linear-gradient(135deg, #005a9e, #003966); /* Dunkleres Blau */
            color: white;
            padding: 20px 40px;
            display: flex;
            flex-direction: column; /* Ermoeglicht Top-Row und Info-Cards untereinander */
            align-items: center; /* Zentriert Info-Cards, falls sie schmaler sind */
        }
        .header-top-row {
            display: flex;
            align-items: center;
            width: 100%;
            margin-bottom: 15px;
        }
        .header-logo {
            width: 125px;
            height: 75px;
            background-color: #e0e0e0;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            color: #333;
            margin-right: 20px;
            flex-shrink: 0;
            border-radius: 4px;
        }
        .header-title { 
            margin: 0; 
            font-size: 2em; 
            font-weight: 500; /* Etwas staerker */
        }
        
        .header-info-cards-container {
            display: flex;
            flex-wrap: wrap;
            justify-content: center; /* Zentriert die Karten */
            gap: 15px; /* Abstand zwischen den Karten */
            padding: 10px 0;
            width: 100%;
            max-width: 1200px; /* Begrenzt die Breite der Kartenreihe */
        }
        .info-card {
            background-color: rgba(255, 255, 255, 0.1); /* Leicht transparente Karten */
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 6px;
            padding: 10px 15px;
            font-size: 0.85em;
            color: white; /* Textfarbe auf den Karten */
            min-width: 150px; /* Mindestbreite fuer Karten */
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .info-card strong {
            display: block;
            font-size: 0.9em;
            color: #b0dfff; /* Hellere Farbe fuer Label */
            margin-bottom: 3px;
        }

        .main-content-wrapper {
            display: flex;
            flex: 1;
            background-color: #f0f2f5; 
            margin: 0;
        }

        .sidebar {
            width: 280px; /* Etwas breiter fuer tiefere Navigation */
            background-color: #ffffff; 
            padding: 20px;
            border-right: 1px solid #d8dde3;
            overflow-y: auto; 
            box-shadow: 2px 0 5px rgba(0,0,0,0.05);
            flex-shrink: 0;
        }
        .sidebar .nav-list {
            list-style: none;
            padding: 0;
            margin: 0;
        }
        .sidebar .nav-item {
            margin-bottom: 6px;
        }
        .sidebar .category-nav .nav-link {
            display: block;
            padding: 12px 15px;
            text-decoration: none;
            color: #33475b; 
            border-radius: 6px;
            transition: background-color 0.2s ease, color 0.2s ease;
            font-size: 0.95em;
            font-weight: 500;
            word-break: break-word;
            border-left: 3px solid transparent;
        }
        .sidebar .category-nav .nav-link:hover {
            background-color: #e9ecef;
            color: #005a9e;
            border-left-color: #005a9e;
        }
        .sidebar .category-nav .nav-link.active {
            background-color: #0078d4;
            color: white;
            font-weight: 600;
            border-left-color: #ffffff;
        }

        .content-area {
            flex: 1; 
            padding: 25px 35px; 
            overflow-y: auto;
            background-color: #ffffff; 
        }
        .content-category-title { /* Stil fuer den Titel im Inhaltsbereich */
            font-size: 1.6em;
            color: #005a9e;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #eef1f5;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
            animation: fadeIn 0.4s ease-in-out;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(8px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .section {
            margin-bottom: 30px;
            background: #ffffff; 
            border-radius: 5px;
            border: 1px solid #e7eaf0; 
            box-shadow: 0 1px 5px rgba(0,0,0,0.05); 
            overflow: hidden;
        }
        .section-header {
            background: #f7f9fc; 
            padding: 12px 18px; /* Etwas kompakter */
            border-bottom: 1px solid #e7eaf0;
        }
        .section-title {
            font-size: 1.15em; 
            font-weight: 600;
            color: #2c3e50; 
            margin: 0;
        }
        .section-content {
            padding: 18px;
        }
        .command-info {
            background-color: #f8f9fa;
            border-left: 4px solid #28a745;
            padding: 10px 15px;
            margin-bottom: 15px;
            font-size: 0.9em;
        }
        .command-info code {
            background-color: #e9ecef;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 0.85em;
            color: #495057;
        }
        pre { 
            background-color: #fdfdff; 
            padding: 12px; 
            border: 1px solid #e0e4e9; 
            border-radius: 4px;
            white-space: pre-wrap; 
            word-wrap: break-word;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 0.85em; 
            line-height: 1.5;
            overflow-x: auto;
            color: #333;
        }

        .footer-timestamp { 
            color: #505050; /* Dunklerer Text */
            font-size: 0.8em;
            text-align: center;
            padding: 15px 40px;
            background-color: #e9ecef; /* Passend zum Rest */
            border-top: 1px solid #d8dde3;
        }
        .footer-timestamp a {
            color: #005a9e;
            text-decoration: none;
        }
        .footer-timestamp a:hover {
            text-decoration: underline;
        }
    </style>
    <script>
        function showTab(tabId, clickedElement) {
            var i, contents, navLinks;
            contents = document.querySelectorAll('.tab-content');
            for (i = 0; i < contents.length; i++) {
                contents[i].classList.remove('active');
            }
            
            navLinks = document.querySelectorAll('.sidebar .category-nav .nav-link');
            for (i = 0; i < navLinks.length; i++) {
                navLinks[i].classList.remove('active');
            }
            
            var selectedTabContent = document.getElementById(tabId);
            if (selectedTabContent) {
                selectedTabContent.classList.add('active');
            }
            
            if (clickedElement) {
                clickedElement.classList.add('active');
            }
        }
        
        window.onload = function() {
            // Ersten Kategorie-Link automatisch aktivieren
            var firstNavLink = document.querySelector('.sidebar .nav-list .category-nav .nav-link');
            if (firstNavLink) {
                firstNavLink.click(); 
            } else {
                // Fallback, falls keine Links vorhanden sind
                var firstContent = document.querySelector('.tab-content');
                if (firstContent) {
                    firstContent.classList.add('active');
                }
            }
        }
    </script>
</head>
<body>
    <div class="page-container">
        <header class="header">
            <div class="header-top-row">
                <div class="header-logo">LOGO</div>
                <h1 class="header-title">$(Convert-ToDisplayString "Windows Server Audit Bericht")</h1>
            </div>
            <div class="header-info-cards-container">
                <div class="info-card"><strong>Hostname:</strong> $(Convert-ToDisplayString $serverInfo.ServerName)</div>
                <div class="info-card"><strong>$(Convert-ToDisplayString "Domäne"):</strong> $(Convert-ToDisplayString $serverInfo.Domain)</div>
                <div class="info-card"><strong>$(Convert-ToDisplayString "Betriebssystem"):</strong> $(Convert-ToDisplayString $serverInfo.OS)</div>
                <div class="info-card"><strong>CPU:</strong> $(Convert-ToDisplayString $serverInfo.CPU)</div>
                <div class="info-card"><strong>RAM:</strong> $(Convert-ToDisplayString $serverInfo.RAM)</div>
                <div class="info-card"><strong>$(Convert-ToDisplayString "Festplatte C: Gesamt"):</strong> $(Convert-ToDisplayString $serverInfo.DiskCTotal)</div>
                <div class="info-card"><strong>$(Convert-ToDisplayString "Festplatte C: Frei"):</strong> $(Convert-ToDisplayString $serverInfo.DiskCFree)</div>
                <div class="info-card"><strong>$(Convert-ToDisplayString "Berichtsdatum"):</strong> $($serverInfo.ReportDate)</div>
                <div class="info-card"><strong>$(Convert-ToDisplayString "Benutzer"):</strong> $(Convert-ToDisplayString $serverInfo.User)</div>
            </div>
        </header>
        
        <div class="main-content-wrapper">
            <nav class="sidebar">
                <ul class="nav-list">
                    $sidebarNavLinks
                </ul>
            </nav>
            <main class="content-area">
                $mainContentTabs
            </main>
        </div>
        
        <footer class="footer-timestamp">
            $(Convert-ToDisplayString "Audit Bericht erstellt von easyWSAudit am $($serverInfo.ReportDate)") | <a href="https://psscripts.de" target="_blank">PSscripts.de</a> | Andreas Hepp
        </footer>
    </div>
</body>
</html>
"@

    $htmlOutput | Out-File -FilePath $FilePath -Encoding utf8
    Write-DebugLog "HTML-Export abgeschlossen" "Export"
}

# Variable fuer die Audit-Ergebnisse
$global:auditResults = @{}

# XAML UI Definition - Vereinfachte Version
[xml]$xaml = @"
<Window 
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="easyWSAudit - Windows Server Audit Tool"
    Height="900" Width="1400" WindowStartupLocation="CenterScreen"
    Background="#F5F5F5">
    <Window.Resources>
        <Style x:Key="ModernButton" TargetType="Button">
            <Setter Property="Background" Value="#0078D4"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="Padding" Value="15,10"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Margin" Value="5"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}" 
                                CornerRadius="4" 
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#106EBE"/>
                </Trigger>
                <Trigger Property="IsEnabled" Value="False">
                    <Setter Property="Background" Value="#CCCCCC"/>
                </Trigger>
            </Style.Triggers>
        </Style>
        
        <Style x:Key="CategoryHeader" TargetType="TextBlock">
            <Setter Property="FontSize" Value="16"/>
            <Setter Property="FontWeight" Value="Bold"/>
            <Setter Property="Foreground" Value="#0078D4"/>
            <Setter Property="Margin" Value="0,15,0,5"/>
        </Style>
        
        <Style x:Key="CheckboxStyle" TargetType="CheckBox">
            <Setter Property="Margin" Value="20,3,5,3"/>
            <Setter Property="Padding" Value="5,0,0,0"/>
        </Style>
    </Window.Resources>
    
    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        
        <!-- Header -->
        <Border Grid.Row="0" Background="#0078D4" Padding="20">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <StackPanel Grid.Column="0">
                    <TextBlock Text="easyWSAudit" FontSize="28" Foreground="White" FontWeight="Light"/>
                    <TextBlock Text="Windows Server Audit Tool" FontSize="14" Foreground="#CCE7FF" Margin="0,5,0,0"/>
                </StackPanel>
                <StackPanel Grid.Column="1" Orientation="Horizontal">
                    <TextBlock x:Name="txtServerName" Text="" FontSize="14" Foreground="White" VerticalAlignment="Center" Margin="0,0,20,0"/>
                    <Button Content="Vollstaendiges Audit" x:Name="btnFullAudit" Style="{StaticResource ModernButton}" Background="#28A745"/>
                </StackPanel>
            </Grid>
        </Border>
        
        <!-- Main Content -->
        <TabControl Grid.Row="1" Margin="20" FontSize="14">
            <TabItem Header="Server Audit-Optionen" FontSize="14">
                <Grid>
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="400"/>
                        <ColumnDefinition Width="*"/>
                    </Grid.ColumnDefinitions>
                    
                    <!-- Linke Seite - Optionen -->
                    <Border Grid.Column="0" Background="White" CornerRadius="8" Padding="20" Margin="0,0,10,0">
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                                <RowDefinition Height="Auto"/>
                            </Grid.RowDefinitions>
                            
                            <StackPanel Grid.Row="0">
                                <TextBlock Text="Audit-Kategorien" FontSize="18" FontWeight="SemiBold" Margin="0,0,0,10"/>
                                <TextBlock Text="Waehlen Sie die Bereiche aus, die Sie auditieren moechten" FontSize="12" Foreground="#6C757D" TextWrapping="Wrap" Margin="0,0,0,15"/>
                            </StackPanel>
                            
                            <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" Margin="0,0,0,15">
                                <StackPanel x:Name="spOptions"/>
                            </ScrollViewer>
                            
                            <StackPanel Grid.Row="2">
                                <Button Content="Alle auswaehlen" x:Name="btnSelectAll" Style="{StaticResource ModernButton}" Background="#28A745" Margin="0,0,0,5"/>
                                <Button Content="Alle abwaehlen" x:Name="btnSelectNone" Style="{StaticResource ModernButton}" Background="#DC3545" Margin="0,0,0,25"/>
                                <Button Content="Audit starten" x:Name="btnRunAudit" Style="{StaticResource ModernButton}" Background="#0078D4" Foreground="White" FontWeight="Bold"/>
                            </StackPanel>
                        </Grid>
                    </Border>
                    
                    <!-- Rechte Seite - Fortschritt -->
                    <Border Grid.Column="1" Background="White" CornerRadius="8" Padding="20" Margin="10,0,0,0">
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>
                            
                            <TextBlock Grid.Row="0" Text="Audit-Fortschritt" FontSize="18" FontWeight="SemiBold" Margin="0,0,0,15"/>
                            
                            <StackPanel Grid.Row="1" Margin="0,0,0,15">
                                <ProgressBar x:Name="progressBar" Height="20" Margin="0,0,0,10"/>
                                <TextBlock x:Name="txtProgress" Text="Bereit fuer Audit" HorizontalAlignment="Center" FontSize="12" Foreground="#666"/>
                            </StackPanel>
                            
                            <Border Grid.Row="2" Background="#F8F9FA" CornerRadius="4" Padding="15">
                                <ScrollViewer VerticalScrollBarVisibility="Auto">
                                    <TextBlock x:Name="txtStatusLog" Text="Bereit..." FontFamily="Consolas" FontSize="11" Foreground="#495057"/>
                                </ScrollViewer>
                            </Border>
                        </Grid>
                    </Border>
                </Grid>
            </TabItem>
            
            <TabItem Header="Audit Ergebnisse" FontSize="14">
                <Grid Margin="20">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>
                    
                    <!-- Toolbar mit Buttons -->
                    <StackPanel Grid.Row="0" Orientation="Horizontal" Margin="0,0,0,15">
                        <Button Content="Als HTML exportieren" x:Name="btnExportHTML" Style="{StaticResource ModernButton}" Background="#17A2B8" IsEnabled="False"/>
                        <Button Content="In Zwischenablage" x:Name="btnCopyToClipboard" Style="{StaticResource ModernButton}" Background="#6C757D" IsEnabled="False" Margin="10,0,0,0"/>
                        <Button Content="Ergebnisse aktualisieren" x:Name="btnRefreshResults" Style="{StaticResource ModernButton}" Background="#28A745" IsEnabled="False" Margin="10,0,0,0"/>
                    </StackPanel>
                    
                    <!-- Kategorien-Auswahl -->
                    <Grid Grid.Row="1" Margin="0,0,0,15">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="250"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        
                        <TextBlock Grid.Column="0" Text="Kategorie:" VerticalAlignment="Center" Margin="0,0,10,0" FontWeight="SemiBold"/>
                        <ComboBox x:Name="cmbResultCategories" Grid.Column="1" Height="30" VerticalAlignment="Center"/>
                        <TextBlock x:Name="txtResultsSummary" Grid.Column="3" Text="" VerticalAlignment="Center" FontSize="12" Foreground="#6C757D"/>
                    </Grid>
                    
                    <!-- Ergebnisse-Anzeige -->
                    <Border Grid.Row="2" Background="White" CornerRadius="8" BorderThickness="1" BorderBrush="#DEE2E6">
                        <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled" 
                                     Padding="0" Margin="0">
                            <RichTextBox x:Name="rtbResults" Background="Transparent" BorderThickness="0" 
                                        IsReadOnly="True" Padding="20" FontFamily="Segoe UI" FontSize="12"
                                        HorizontalAlignment="Stretch" VerticalAlignment="Stretch"/>
                        </ScrollViewer>
                    </Border>
                </Grid>
            </TabItem>
            
            <TabItem Header="Verbindungsaudit" FontSize="14">
                <Grid Margin="20">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="400"/>
                        <ColumnDefinition Width="*"/>
                    </Grid.ColumnDefinitions>
                    
                    <!-- Linke Seite - Verbindungsaudit Optionen -->
                    <Border Grid.Column="0" Background="White" CornerRadius="8" Padding="20" Margin="0,0,10,0">
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                                <RowDefinition Height="Auto"/>
                            </Grid.RowDefinitions>
                            
                            <StackPanel Grid.Row="0">
                                <TextBlock Text="Verbindungsaudit-Kategorien" FontSize="18" FontWeight="SemiBold" Margin="0,0,0,10"/>
                                <TextBlock Text="Analyse aktiver Netzwerkverbindungen, Geraete und Benutzer" FontSize="12" Foreground="#6C757D" TextWrapping="Wrap" Margin="0,0,0,15"/>
                            </StackPanel>
                            
                            <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" Margin="0,0,0,15">
                                <StackPanel x:Name="spConnectionOptions"/>
                            </ScrollViewer>
                            
                            <StackPanel Grid.Row="2">
                                <Button Content="Alle auswaehlen" x:Name="btnSelectAllConnection" Style="{StaticResource ModernButton}" Background="#28A745" Margin="0,0,0,5"/>
                                <Button Content="Alle abwaehlen" x:Name="btnSelectNoneConnection" Style="{StaticResource ModernButton}" Background="#DC3545" Margin="0,0,0,25"/>
                                <Button Content="Verbindungsaudit starten" x:Name="btnRunConnectionAudit" Style="{StaticResource ModernButton}" Background="#FD7E14" Foreground="White" FontWeight="Bold"/>
                            </StackPanel>
                        </Grid>
                    </Border>
                    
                    <!-- Rechte Seite - Verbindungsaudit Ergebnisse -->
                    <Border Grid.Column="1" Background="White" CornerRadius="8" Padding="20" Margin="10,0,0,0">
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>
                            
                            <TextBlock Grid.Row="0" Text="Verbindungsaudit-Ergebnisse" FontSize="18" FontWeight="SemiBold" Margin="0,0,0,15"/>
                            
                            <!-- Fortschritt fuer Verbindungsaudit -->
                            <StackPanel Grid.Row="1" Margin="0,0,0,15">
                                <ProgressBar x:Name="progressBarConnection" Height="20" Margin="0,0,0,10"/>
                                <TextBlock x:Name="txtProgressConnection" Text="Bereit fuer Verbindungsaudit" HorizontalAlignment="Center" FontSize="12" Foreground="#666"/>
                            </StackPanel>
                            
                            <!-- Toolbar fuer Verbindungsaudit -->
                            <StackPanel Grid.Row="2" Orientation="Horizontal" Margin="0,0,0,15">
                                <Button Content="Export HTML" x:Name="btnExportConnectionHTML" Style="{StaticResource ModernButton}" Background="#17A2B8" IsEnabled="False"/>
                                <Button Content="Export DRAW.IO" x:Name="btnExportConnectionDrawIO" Style="{StaticResource ModernButton}" Background="#28A745" IsEnabled="False" Margin="10,0,0,0"/>
                                <Button Content="In Zwischenablage" x:Name="btnCopyConnectionToClipboard" Style="{StaticResource ModernButton}" Background="#6C757D" IsEnabled="False" Margin="10,0,0,0"/>
                                <ComboBox x:Name="cmbConnectionCategories" Width="200" Height="30" VerticalAlignment="Center" Margin="20,0,0,0" IsEnabled="False"/>
                            </StackPanel>
                            
                            <!-- Ergebnisse-Anzeige fuer Verbindungsaudit -->
                            <Border Grid.Row="3" Background="#F8F9FA" CornerRadius="4" BorderThickness="1" BorderBrush="#DEE2E6">
                                <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled" 
                                             Padding="0" Margin="0">
                                    <RichTextBox x:Name="rtbConnectionResults" Background="Transparent" BorderThickness="0" 
                                                IsReadOnly="True" Padding="20" FontFamily="Segoe UI" FontSize="12"
                                                HorizontalAlignment="Stretch" VerticalAlignment="Stretch"/>
                                </ScrollViewer>
                            </Border>
                        </Grid>
                    </Border>
                </Grid>
            </TabItem>
            
            <TabItem Header="Debug" FontSize="14">
                <Grid Margin="20">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>
                    
                    <TextBlock Grid.Row="0" Text="Debug-Informationen" FontSize="18" FontWeight="SemiBold" Margin="0,0,0,15"/>
                    
                    <Border Grid.Row="1" Background="#1E1E1E" CornerRadius="8" BorderThickness="1" BorderBrush="#333333">
                        <ScrollViewer VerticalScrollBarVisibility="Auto">
                            <TextBox x:Name="txtDebugOutput" Background="Transparent" BorderThickness="0" 
                                     FontFamily="Consolas" IsReadOnly="True" TextWrapping="Wrap"
                                     Foreground="#00FF00" Padding="15" FontSize="11"/>
                        </ScrollViewer>
                    </Border>
                    
                    <StackPanel Grid.Row="2" Orientation="Horizontal" Margin="0,15,0,0" HorizontalAlignment="Left">
                        <Button Content="Log-Datei oeffnen" x:Name="btnOpenLog" Style="{StaticResource ModernButton}"/>
                        <Button Content="Log leeren" x:Name="btnClearLog" Style="{StaticResource ModernButton}" Background="#DC3545" Margin="10,0,0,0"/>
                    </StackPanel>
                </Grid>
            </TabItem>
        </TabControl>
        
        <!-- Footer -->
        <Border Grid.Row="2" Background="#F8F9FA" BorderThickness="0,1,0,0" BorderBrush="#DEE2E6" Padding="20,10">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <TextBlock x:Name="txtStatus" Text="Status: Bereit" VerticalAlignment="Center" FontSize="12" Foreground="#6C757D"/>
                <TextBlock Grid.Column="1" Text="PSscripts.de | easyWSAudit v0.0.3 - 23.05.2025  |  Andreas Hepp" VerticalAlignment="Center" FontSize="12" Foreground="#6C757D"/>
            </Grid>
        </Border>
    </Grid>
</Window>
"@

# Lade das XAML
Write-DebugLog "Lade XAML fuer UI..." "UI"
try {
    $reader = [System.Xml.XmlNodeReader]::new($xaml)
    $window = [Windows.Markup.XamlReader]::Load($reader)
    
    if ($null -eq $window) {
        throw "Window konnte nicht erstellt werden"
    }
    
    Write-DebugLog "XAML erfolgreich geladen, Fenster erstellt" "UI"
} catch {
    Write-DebugLog "FEHLER beim Laden des XAML: $($_.Exception.Message)" "UI"
    Write-Host "KRITISCHER FEHLER beim Laden der UI: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Details: $($_.Exception.ToString())" -ForegroundColor Red
    
    # Zeige eine Fehlermeldung und beende das Script
    if ($_.Exception.InnerException) {
        Write-Host "Innere Exception: $($_.Exception.InnerException.Message)" -ForegroundColor Red
    }
    
    Read-Host "Drücken Sie eine Taste zum Beenden"
    return
}

# Hole die UI-Elemente
Write-DebugLog "Suche UI-Elemente..." "UI"
$txtServerName = $window.FindName("txtServerName")
$btnFullAudit = $window.FindName("btnFullAudit")
$spOptions = $window.FindName("spOptions")
$btnSelectAll = $window.FindName("btnSelectAll")
$btnSelectNone = $window.FindName("btnSelectNone")
$btnRunAudit = $window.FindName("btnRunAudit")
$progressBar = $window.FindName("progressBar")
$txtProgress = $window.FindName("txtProgress")
$txtStatusLog = $window.FindName("txtStatusLog")
$cmbResultCategories = $window.FindName("cmbResultCategories")
$rtbResults = $window.FindName("rtbResults")
$txtResultsSummary = $window.FindName("txtResultsSummary")
$btnExportHTML = $window.FindName("btnExportHTML")
$btnCopyToClipboard = $window.FindName("btnCopyToClipboard")
$btnRefreshResults = $window.FindName("btnRefreshResults")
$txtStatus = $window.FindName("txtStatus")

# Verbindungsaudit-Elemente
$spConnectionOptions = $window.FindName("spConnectionOptions")
$btnSelectAllConnection = $window.FindName("btnSelectAllConnection")
$btnSelectNoneConnection = $window.FindName("btnSelectNoneConnection")
$btnRunConnectionAudit = $window.FindName("btnRunConnectionAudit")
$progressBarConnection = $window.FindName("progressBarConnection")
$txtProgressConnection = $window.FindName("txtProgressConnection")
$btnExportConnectionHTML = $window.FindName("btnExportConnectionHTML")
$btnExportConnectionDrawIO = $window.FindName("btnExportConnectionDrawIO")
$btnCopyConnectionToClipboard = $window.FindName("btnCopyConnectionToClipboard")
$cmbConnectionCategories = $window.FindName("cmbConnectionCategories")
$rtbConnectionResults = $window.FindName("rtbConnectionResults")

# Debug-Elemente
$script:txtDebugOutput = $window.FindName("txtDebugOutput")
$btnOpenLog = $window.FindName("btnOpenLog")
$btnClearLog = $window.FindName("btnClearLog")

# Überprüfe kritische UI-Elemente
Write-DebugLog "Überprüfe UI-Elemente..." "UI"
if ($null -eq $window) { Write-DebugLog "FEHLER: window ist NULL!" "UI"; return }
if ($null -eq $spOptions) { Write-DebugLog "FEHLER: spOptions ist NULL!" "UI"; return }
if ($null -eq $txtServerName) { Write-DebugLog "FEHLER: txtServerName ist NULL!" "UI"; return }
if ($null -eq $spConnectionOptions) { Write-DebugLog "FEHLER: spConnectionOptions ist NULL!" "UI"; return }

Write-DebugLog "UI-Elemente erfolgreich initialisiert" "UI"

# Servername anzeigen
$txtServerName.Text = "Server: $env:COMPUTERNAME"

# Dictionary fuer Checkboxen (beide Audits)
$checkboxes = @{}
$connectionCheckboxes = @{}

# Erstelle die Checkboxen fuer die Verbindungsaudit-Optionen
Write-DebugLog "Erstelle Checkboxen fuer Verbindungsaudit-Optionen..." "UI"

$connectionCategories = @{}
foreach ($cmd in $connectionAuditCommands) {
    $categoryName = if ($cmd.Category) { $cmd.Category } else { "Allgemein" }
    if (-not $connectionCategories.ContainsKey($categoryName)) {
        $connectionCategories[$categoryName] = @()
    }
    $connectionCategories[$categoryName] += $cmd
}

# Iteriere über die Verbindungsaudit-Kategorien in alphabetischer Reihenfolge
foreach ($categoryKey in ($connectionCategories.Keys | Sort-Object)) {
    # Kategorie-Header
    $categoryHeader = New-Object System.Windows.Controls.TextBlock
    $categoryHeader.Text = "$categoryKey"
    
    # Setze Style direkt
    $categoryHeader.FontSize = 16
    $categoryHeader.FontWeight = "Bold"
    $categoryHeader.Foreground = New-Object System.Windows.Media.SolidColorBrush([System.Windows.Media.Color]::FromRgb(253, 126, 20)) # Orange für Verbindungsaudit
    $categoryHeader.Margin = New-Object System.Windows.Thickness(0, 15, 0, 5)
    
    try {
        $spConnectionOptions.Children.Add($categoryHeader)
        Write-DebugLog "Verbindungsaudit Kategorie-Header '$categoryKey' hinzugefügt" "UI"
    } catch {
        Write-DebugLog "FEHLER beim Hinzufügen des Verbindungsaudit Kategorie-Headers '$categoryKey': $($_.Exception.Message)" "UI"
        continue
    }
    
    # Checkboxen fuer diese Kategorie
    foreach ($cmd in $connectionCategories[$categoryKey]) {
        $checkbox = New-Object System.Windows.Controls.CheckBox
        $checkbox.Content = $cmd.Name
        $checkbox.IsChecked = $true # Standardmäßig aktiviert
        
        # Setze Style direkt
        $checkbox.Margin = New-Object System.Windows.Thickness(20, 3, 5, 3)
        $checkbox.Padding = New-Object System.Windows.Thickness(5, 0, 0, 0)
        
        # Ueberpruefe, ob diese Option mit einer Serverrolle verbunden ist
        if ($cmd.ContainsKey("FeatureName")) {
            $isRoleInstalled = Test-ServerRole -FeatureName $cmd.FeatureName
            if (-not $isRoleInstalled) {
                $checkbox.IsEnabled = $false
                $checkbox.Content = "$($cmd.Name) (Nicht installiert)"
                $checkbox.IsChecked = $false
            }
        }
        
        try {
            $spConnectionOptions.Children.Add($checkbox)
            $connectionCheckboxes[$cmd.Name] = $checkbox
            Write-DebugLog "Verbindungsaudit Checkbox '$($cmd.Name)' hinzugefügt (Kategorie: $categoryKey)" "UI"
        } catch {
            Write-DebugLog "FEHLER beim Hinzufügen der Verbindungsaudit Checkbox '$($cmd.Name)' (Kategorie: $categoryKey): $($_.Exception.Message)" "UI"
        }
    }
}
Write-DebugLog "Verbindungsaudit Checkboxen erstellt für $($connectionCheckboxes.Count) Optionen" "UI"

# Dictionary fuer Checkboxen
$checkboxes = @{}

# Erstelle die Checkboxen fuer die Audit-Optionen gruppiert nach Kategorien
Write-DebugLog "Erstelle Checkboxen fuer Audit-Optionen..." "UI"

# Überprüfe, ob spOptions verfügbar ist
if ($null -eq $spOptions) {
    Write-DebugLog "FEHLER: spOptions nicht gefunden - kann keine Checkboxen erstellen!" "UI"
    [System.Windows.MessageBox]::Show("UI-Initialisierungsfehler: spOptions nicht gefunden.", "Fehler", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    return
}

$categories = @{} # Verwende ein normales Hashtable für bessere Kompatibilität
foreach ($cmd in $commands) {
    $categoryName = if ($cmd.Category) { $cmd.Category } else { "Allgemein" }
    if (-not $categories.ContainsKey($categoryName)) {
        # Initialisiere den Eintrag für eine neue Kategorie mit einer Liste.
        $categories[$categoryName] = @()
    }
    # Füge den Befehl zur Liste der entsprechenden Kategorie hinzu
    $categories[$categoryName] += $cmd
}

# Iteriere über die Kategorien in alphabetischer Reihenfolge
foreach ($categoryKey in ($categories.Keys | Sort-Object)) {
    # Kategorie-Header
    $categoryHeader = New-Object System.Windows.Controls.TextBlock
    $categoryHeader.Text = "$categoryKey"
    
    # Setze Style direkt statt über FindResource
    $categoryHeader.FontSize = 16
    $categoryHeader.FontWeight = "Bold"
    $categoryHeader.Foreground = New-Object System.Windows.Media.SolidColorBrush([System.Windows.Media.Color]::FromRgb(0, 120, 212))
    $categoryHeader.Margin = New-Object System.Windows.Thickness(0, 15, 0, 5)
    
    try {
        $spOptions.Children.Add($categoryHeader)
        Write-DebugLog "Kategorie-Header '$categoryKey' hinzugefügt" "UI"
    } catch {
        Write-DebugLog "FEHLER beim Hinzufügen des Kategorie-Headers '$categoryKey': $($_.Exception.Message)" "UI"
        continue # Springe zur nächsten Kategorie, falls der Header nicht hinzugefügt werden kann
    }
    
    # Checkboxen fuer diese Kategorie
    # $categories[$categoryKey] enthält eine Liste von Befehls-Hashtables für die aktuelle Kategorie
    foreach ($cmd in $categories[$categoryKey]) {
        $checkbox = New-Object System.Windows.Controls.CheckBox
        $checkbox.Content = $cmd.Name
        $checkbox.IsChecked = $true # Standardmäßig aktiviert
        
        # Setze Style direkt statt über FindResource
        $checkbox.Margin = New-Object System.Windows.Thickness(20, 3, 5, 3)
        $checkbox.Padding = New-Object System.Windows.Thickness(5, 0, 0, 0)
        
        # Ueberpruefe, ob diese Option mit einer Serverrolle verbunden ist
        if ($cmd.ContainsKey("FeatureName")) {
            # Test-ServerRole ist eine Funktion, die prüft, ob eine Windows-Funktion/Rolle installiert ist.
            # Diese Funktion ist außerhalb dieses Codeblocks definiert.
            $isRoleInstalled = Test-ServerRole -FeatureName $cmd.FeatureName
            if (-not $isRoleInstalled) {
                $checkbox.IsEnabled = $false
                $checkbox.Content = "$($cmd.Name) (Nicht installiert)"
                $checkbox.IsChecked = $false # Deaktiviere Checkbox, wenn zugehörige Rolle nicht installiert ist
            }
        }
        
        try {
            $spOptions.Children.Add($checkbox)
            $checkboxes[$cmd.Name] = $checkbox # Speichere eine Referenz zur Checkbox im globalen Hashtable
            Write-DebugLog "Checkbox '$($cmd.Name)' hinzugefügt (Kategorie: $categoryKey)" "UI"
        } catch {
            Write-DebugLog "FEHLER beim Hinzufügen der Checkbox '$($cmd.Name)' (Kategorie: $categoryKey): $($_.Exception.Message)" "UI"
            # Fahre mit der nächsten Checkbox fort, auch wenn eine fehlschlägt
        }
    }
}
Write-DebugLog "Checkboxen erstellt fuer $($checkboxes.Count) Optionen" "UI"

# Button-Event-Handler

# "Alle auswaehlen" Button
$btnSelectAll.Add_Click({
    Write-DebugLog "Alle Optionen auswaehlen" "UI"
    foreach ($key in $checkboxes.Keys) {
        if ($checkboxes[$key].IsEnabled) {
            $checkboxes[$key].IsChecked = $true
        }
    }
})

# "Alle abwaehlen" Button
$btnSelectNone.Add_Click({
    Write-DebugLog "Alle Optionen abwaehlen" "UI"
    foreach ($key in $checkboxes.Keys) {
        $checkboxes[$key].IsChecked = $false
    }
})

# Verbindungsaudit Button-Event-Handler

# "Alle auswaehlen" Button (Verbindungsaudit)
$btnSelectAllConnection.Add_Click({
    Write-DebugLog "Alle Verbindungsaudit-Optionen auswaehlen" "UI"
    foreach ($key in $connectionCheckboxes.Keys) {
        if ($connectionCheckboxes[$key].IsEnabled) {
            $connectionCheckboxes[$key].IsChecked = $true
        }
    }
})

# "Alle abwaehlen" Button (Verbindungsaudit)
$btnSelectNoneConnection.Add_Click({
    Write-DebugLog "Alle Verbindungsaudit-Optionen abwaehlen" "UI"
    foreach ($key in $connectionCheckboxes.Keys) {
        $connectionCheckboxes[$key].IsChecked = $false
    }
})

# "Verbindungsaudit starten" Button
$btnRunConnectionAudit.Add_Click({
    Write-DebugLog "Verbindungsaudit gestartet" "ConnectionAudit"
    
    # UI vorbereiten
    $btnRunConnectionAudit.IsEnabled = $false
    $btnExportConnectionHTML.IsEnabled = $false
    $btnExportConnectionDrawIO.IsEnabled = $false
    $btnCopyConnectionToClipboard.IsEnabled = $false
    $cmbConnectionCategories.IsEnabled = $false
    
    $rtbConnectionResults.Document = New-Object System.Windows.Documents.FlowDocument
    $progressBarConnection.Value = 0
    $txtProgressConnection.Text = "Initialisiere Verbindungsaudit..."
    
    # Sammle ausgewählte Befehle
    $selectedConnectionCommands = @()
    foreach ($cmd in $connectionAuditCommands) {
        if ($connectionCheckboxes[$cmd.Name].IsChecked) {
            $selectedConnectionCommands += $cmd
        }
    }
    
    if ($selectedConnectionCommands.Count -eq 0) {
        [System.Windows.MessageBox]::Show("Bitte wählen Sie mindestens eine Verbindungsaudit-Option aus.", "Keine Auswahl", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        $btnRunConnectionAudit.IsEnabled = $true
        return
    }
    
    $global:connectionAuditResults = @{}
    $progressStep = 100.0 / $selectedConnectionCommands.Count
    $currentProgress = 0
    
    for ($i = 0; $i -lt $selectedConnectionCommands.Count; $i++) {
        $cmd = $selectedConnectionCommands[$i]
        
        $window.Dispatcher.Invoke([Action]{
            $txtProgressConnection.Text = "Verarbeite: $($cmd.Name) ($($i+1)/$($selectedConnectionCommands.Count))"
            $progressBarConnection.Value = $currentProgress
        }, "Normal")
        
        # UI refresh erzwingen
        $window.Dispatcher.Invoke([Action]{}, "ApplicationIdle")
        [System.Windows.Forms.Application]::DoEvents()
        Start-Sleep -Milliseconds 100
        
        Write-DebugLog "Fuehre Verbindungsaudit aus ($($i+1)/$($selectedConnectionCommands.Count)): $($cmd.Name)" "ConnectionAudit"
        
        try {
            if ($cmd.Type -eq "PowerShell") {
                $result = Invoke-PSCommand -Command $cmd.Command
            } else {
                $result = Invoke-CMDCommand -Command $cmd.Command
            }
            
            $global:connectionAuditResults[$cmd.Name] = $result
            $currentProgress += $progressStep
            
            $window.Dispatcher.Invoke([Action]{
                $progressBarConnection.Value = $currentProgress
            }, "Normal")
            
        } catch {
            $errorMsg = "Fehler: $($_.Exception.Message)"
            $global:connectionAuditResults[$cmd.Name] = $errorMsg
            $currentProgress += $progressStep
            
            $window.Dispatcher.Invoke([Action]{
                $progressBarConnection.Value = $currentProgress
            }, "Normal")
            
            Write-DebugLog "FEHLER bei Verbindungsaudit $($cmd.Name): $($_.Exception.Message)" "ConnectionAudit"
        }
        
        # UI refresh erzwingen
        $window.Dispatcher.Invoke([Action]{}, "ApplicationIdle")
        [System.Windows.Forms.Application]::DoEvents()
        Start-Sleep -Milliseconds 100
    }
    
    # Verbindungsaudit abgeschlossen
    $window.Dispatcher.Invoke([Action]{
        $progressBarConnection.Value = 100
        $txtProgressConnection.Text = "Verbindungsaudit abgeschlossen! $($selectedConnectionCommands.Count) Befehle ausgefuehrt."
        
        # Zeige Ergebnisse an
        try {
            Update-ConnectionResultsCategories
            Show-ConnectionResults -Category "Alle"
        } catch {
            Write-DebugLog "FEHLER beim Anzeigen der Verbindungsaudit-Ergebnisse: $($_.Exception.Message)" "ConnectionAudit"
            Show-SimpleConnectionResults
        }
        
        # Buttons wieder aktivieren
        $btnRunConnectionAudit.IsEnabled = $true
        $btnExportConnectionHTML.IsEnabled = $true
        $btnExportConnectionDrawIO.IsEnabled = $true
        $btnCopyConnectionToClipboard.IsEnabled = $true
        $cmbConnectionCategories.IsEnabled = $true
        
    }, "Normal")
    
    Write-DebugLog "Verbindungsaudit abgeschlossen mit $($global:connectionAuditResults.Count) Ergebnissen" "ConnectionAudit"
})

# ComboBox Selection Changed Event
$cmbResultCategories.Add_SelectionChanged({
    if ($cmbResultCategories.SelectedItem) {
        $selectedCategory = $cmbResultCategories.SelectedItem.Tag
        Show-CategoryResults -Category $selectedCategory
    }
})

# "Ergebnisse aktualisieren" Button
$btnRefreshResults.Add_Click({
    Write-DebugLog "Aktualisiere Ergebnisse-Anzeige" "UI"
    
    try {
        # Versuche die RichTextBox zurückzusetzen
        Reset-ResultsDisplay
        
        # Aktualisiere Kategorien
        Update-ResultsCategories
        
        # Zeige die ausgewählte Kategorie erneut an
        if ($cmbResultCategories.SelectedItem) {
            $selectedCategory = $cmbResultCategories.SelectedItem.Tag
            Show-CategoryResults -Category $selectedCategory
        } else {
            Show-CategoryResults -Category "Alle"
        }
        
        $txtStatus.Text = "Status: Ergebnisse erfolgreich aktualisiert"
    }
    catch {
        Write-DebugLog "FEHLER beim Aktualisieren der Ergebnisse: $($_.Exception.Message)" "UI"
        $txtStatus.Text = "Status: Fehler beim Aktualisieren der Ergebnisse"
        [System.Windows.MessageBox]::Show("Fehler beim Aktualisieren der Ergebnisse:`r`n$($_.Exception.Message)", "Fehler", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        
        # Fallback: Zeige Ergebnisse in einfacher Form
        Show-SimpleResults -Category "Alle"
    }
})

# Funktion zum Zurücksetzen der Ergebnisanzeige
function Reset-ResultsDisplay {
    Write-DebugLog "Setze Ergebnisanzeige zurück" "UI"
    
    try {
        # Erstelle ein komplett neues, leeres FlowDocument
        $newDocument = New-Object System.Windows.Documents.FlowDocument
        $newDocument.FontFamily = New-Object System.Windows.Media.FontFamily("Segoe UI")
        $newDocument.FontSize = 12
        $newDocument.PageWidth = [Double]::NaN
        $newDocument.PageHeight = [Double]::NaN
        $newDocument.ColumnWidth = [Double]::PositiveInfinity
        
        # Setze das neue Dokument
        $rtbResults.Document = $newDocument
        
        # Erzwinge Update
        $rtbResults.UpdateLayout()
        
        Write-DebugLog "Ergebnisanzeige erfolgreich zurückgesetzt" "UI"
    }
    catch {
        Write-DebugLog "FEHLER beim Zurücksetzen der Ergebnisanzeige: $($_.Exception.Message)" "UI"
        throw $_
    }
}

# Hilfsfunktion zum Optimieren der RichTextBox für besseres Text-Wrapping
function Optimize-RichTextBoxLayout {
    try {
        Write-DebugLog "Optimiere RichTextBox-Layout" "UI"
        
        # Setze die RichTextBox-Eigenschaften für optimales Wrapping
        $rtbResults.HorizontalScrollBarVisibility = "Disabled"
        $rtbResults.VerticalScrollBarVisibility = "Disabled" # ScrollViewer übernimmt das Scrolling
        
        # Stelle sicher, dass das Document korrekt konfiguriert ist
        if ($rtbResults.Document) {
            $rtbResults.Document.PageWidth = [Double]::NaN
            $rtbResults.Document.PageHeight = [Double]::NaN
            $rtbResults.Document.ColumnWidth = [Double]::PositiveInfinity
            $rtbResults.Document.TextAlignment = "Left"
        }
        
        Write-DebugLog "RichTextBox-Layout optimiert" "UI"
    }
    catch {
        Write-DebugLog "WARNUNG: Konnte RichTextBox-Layout nicht optimieren: $($_.Exception.Message)" "UI"
        # Fehler ignorieren, da dies nur eine Optimierung ist
    }
}

# Vollstaendiges Audit Button
$btnFullAudit.Add_Click({
    Write-DebugLog "Vollstaendiges Audit gestartet" "Audit"
    # Alle verfuegbaren Optionen auswaehlen
    foreach ($key in $checkboxes.Keys) {
        if ($checkboxes[$key].IsEnabled) {
            $checkboxes[$key].IsChecked = $true
        }
    }
    # Audit starten
    Start-AuditProcess
})

# "Audit starten" Button
$btnRunAudit.Add_Click({
    Write-DebugLog "Benutzerdefiniertes Audit gestartet" "Audit"
    Start-AuditProcess
})

# Hauptfunktion fuer die Audit-Durchfuehrung (Synchron)
function Start-AuditProcess {
    # UI vorbereiten
    $btnRunAudit.IsEnabled = $false
    $btnFullAudit.IsEnabled = $false
    $btnExportHTML.IsEnabled = $false
    $btnCopyToClipboard.IsEnabled = $false
    $btnRefreshResults.IsEnabled = $false
    
    $rtbResults.Document = New-Object System.Windows.Documents.FlowDocument
    $txtStatusLog.Text = ""
    $progressBar.Value = 0
    $txtStatus.Text = "Status: Audit laeuft..."
    
    # UI initial aktualisieren
    $window.Dispatcher.Invoke([Action]{
        $txtProgress.Text = "Initialisiere Audit..."
        $txtStatusLog.Text = "=== Audit gestartet ===`r`n"
        $progressBar.Value = 0
    }, "Normal")
    
    # UI refresh erzwingen
    $window.Dispatcher.Invoke([Action]{}, "ApplicationIdle")
    Start-Sleep -Milliseconds 300
    
    # Sammle ausgewaehlte Befehle
    $selectedCommands = @()
    foreach ($cmd in $commands) {
        if ($checkboxes[$cmd.Name].IsChecked) {
            $selectedCommands += $cmd
        }
    }
    
    Write-DebugLog "Starte Audit mit $($selectedCommands.Count) ausgewaehlten Befehlen" "Audit"
    
    $global:auditResults = @{}
    $allResults = ""
    $progressStep = 100.0 / $selectedCommands.Count
    $currentProgress = 0
    
    # UI Update mit Anzahl der Befehle
    $window.Dispatcher.Invoke([Action]{
        $txtProgress.Text = "Bereite $($selectedCommands.Count) Audit-Befehle vor..."
        $txtStatusLog.Text += "Anzahl ausgewaehlter Befehle: $($selectedCommands.Count)`r`n`r`n"
    }, "Normal")
    
    # UI refresh erzwingen
    $window.Dispatcher.Invoke([Action]{}, "ApplicationIdle")
    Start-Sleep -Milliseconds 500
    
    for ($i = 0; $i -lt $selectedCommands.Count; $i++) {
        $cmd = $selectedCommands[$i]
        
        # UI aktualisieren - BEGINN des Befehls
        $window.Dispatcher.Invoke([Action]{
            $txtProgress.Text = "Verarbeite: $($cmd.Name) ($($i+1)/$($selectedCommands.Count))"
            $txtStatusLog.Text += "[$($i+1)/$($selectedCommands.Count)] $($cmd.Name)...`r`n"
            # Fortschritt am Anfang des Befehls anzeigen
            $progressBar.Value = $currentProgress
        }, "Normal")
        
        # UI refresh erzwingen - das ist der Schluessel!
        $window.Dispatcher.Invoke([Action]{}, "ApplicationIdle")
        [System.Windows.Forms.Application]::DoEvents()
        Start-Sleep -Milliseconds 200
        
        Write-DebugLog "Fuehre aus ($($i+1)/$($selectedCommands.Count)): $($cmd.Name)" "Audit"
        
        try {
            if ($cmd.Type -eq "PowerShell") {
                $result = Invoke-PSCommand -Command $cmd.Command
            } else {
                $result = Invoke-CMDCommand -Command $cmd.Command
            }
            
            $global:auditResults[$cmd.Name] = $result
            $allResults += "`r`n=== $($cmd.Name) ===`r`n$result`r`n"
            
            # Erfolg in Status-Log UND Fortschrittsbalken aktualisieren
            $currentProgress += $progressStep
            $window.Dispatcher.Invoke([Action]{
                $txtStatusLog.Text += "  [OK] Erfolgreich abgeschlossen`r`n"
                # Fortschrittsbalken NACH erfolgreichem Befehl aktualisieren
                $progressBar.Value = $currentProgress
                $txtProgress.Text = "Abgeschlossen: $($cmd.Name) ($($i+1)/$($selectedCommands.Count))"
            }, "Normal")
            
        } catch {
            $errorMsg = "Fehler: $($_.Exception.Message)"
            $global:auditResults[$cmd.Name] = $errorMsg
            $allResults += "`r`n=== $($cmd.Name) ===`r`n$errorMsg`r`n"
            
            # Fehler in Status-Log UND Fortschrittsbalken trotzdem aktualisieren
            $currentProgress += $progressStep
            $window.Dispatcher.Invoke([Action]{
                $txtStatusLog.Text += "  [FEHLER] $($_.Exception.Message)`r`n"
                # Fortschrittsbalken auch bei Fehler aktualisieren
                $progressBar.Value = $currentProgress
                $txtProgress.Text = "Fehler bei: $($cmd.Name) ($($i+1)/$($selectedCommands.Count))"
            }, "Normal")
            
            Write-DebugLog "FEHLER bei $($cmd.Name): $($_.Exception.Message)" "Audit"
        }
        
        # UI refresh nach jedem Befehl erzwingen - SEHR WICHTIG!
        $window.Dispatcher.Invoke([Action]{}, "ApplicationIdle")
        [System.Windows.Forms.Application]::DoEvents()
        Start-Sleep -Milliseconds 300
        
        # Zwischenstand der Ergebnisse aktualisieren (optional)
        if (($i + 1) % 3 -eq 0 -or $i -eq ($selectedCommands.Count - 1)) {
            $window.Dispatcher.Invoke([Action]{
                try {
                    # Aktualisiere die schöne Anzeige statt der alten Textbox
                    Update-ResultsCategories
                    if ($cmbResultCategories.SelectedItem) {
                        $selectedCategory = $cmbResultCategories.SelectedItem.Tag
                        Show-CategoryResults -Category $selectedCategory
                    } else {
                        Show-CategoryResults -Category "Alle"
                    }
                }
                catch {
                    Write-DebugLog "FEHLER beim Zwischenupdate der Ergebnisanzeige: $($_.Exception.Message)" "Audit"
                    # Bei Fehlern trotzdem fortfahren
                }
            }, "Normal")
            # UI refresh auch hier
            $window.Dispatcher.Invoke([Action]{}, "ApplicationIdle")
            [System.Windows.Forms.Application]::DoEvents()
        }
    }
    
    # Audit abgeschlossen - Finale Updates
    $window.Dispatcher.Invoke([Action]{
        $progressBar.Value = 100
        $txtProgress.Text = "Audit vollstaendig abgeschlossen! $($selectedCommands.Count) Befehle ausgefuehrt."
        $txtStatusLog.Text += "`r`n" + "="*50 + "`r`n"
        $txtStatusLog.Text += "[FERTIG] Audit erfolgreich abgeschlossen!`r`n"
        $txtStatusLog.Text += "Ergebnisse: $($global:auditResults.Count) Eintraege`r`n"
        $txtStatusLog.Text += "="*50 + "`r`n"
        
        try {
            # Aktualisiere die schöne Kategorien-Anzeige
            Update-ResultsCategories
            Show-CategoryResults -Category "Alle"
        }
        catch {
            Write-DebugLog "FEHLER beim finalen Update der Ergebnisanzeige: $($_.Exception.Message)" "Audit"
            # Fallback auf einfache Anzeige
            try {
                Show-SimpleResults -Category "Alle"
                $txtStatusLog.Text += "[WARNUNG] Verwendet einfache Ergebnisanzeige aufgrund von Formatierungsproblemen`r`n"
            }
            catch {
                Write-DebugLog "FEHLER auch bei einfacher Anzeige: $($_.Exception.Message)" "Audit"
                $txtStatusLog.Text += "[FEHLER] Konnte Ergebnisse nicht anzeigen - siehe Debug-Log`r`n"
            }
        }
        
        $txtStatus.Text = "Status: Audit abgeschlossen - $($global:auditResults.Count) Ergebnisse"
        
        # Buttons wieder aktivieren
        $btnRunAudit.IsEnabled = $true
        $btnFullAudit.IsEnabled = $true
        $btnExportHTML.IsEnabled = $true
        $btnCopyToClipboard.IsEnabled = $true
        $btnRefreshResults.IsEnabled = $true
    }, "Normal")
    
    # Finaler UI refresh
    $window.Dispatcher.Invoke([Action]{}, "ApplicationIdle")
    [System.Windows.Forms.Application]::DoEvents()
    
    Write-DebugLog "Audit abgeschlossen mit $($global:auditResults.Count) Ergebnissen" "Audit"
}

# Export-Button-Funktionalitaet
$btnExportHTML.Add_Click({
    Write-DebugLog "HTML-Export gestartet" "Export"
    
    $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveFileDialog.Filter = "HTML Files (*.html)|*.html"
    $saveFileDialog.Title = "Speichern Sie den Audit-Bericht"
    $saveFileDialog.FileName = "ServerAudit_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    
    if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $txtStatus.Text = "Status: Exportiere HTML..."
        
        try {
            Export-AuditToHTML -Results $global:auditResults -FilePath $saveFileDialog.FileName
            $txtStatus.Text = "Status: Export erfolgreich abgeschlossen"
            [System.Windows.MessageBox]::Show("Bericht wurde erfolgreich exportiert:`r`n$($saveFileDialog.FileName)", "Export erfolgreich", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        } catch {
            $txtStatus.Text = "Status: Fehler beim Export"
            [System.Windows.MessageBox]::Show("Fehler beim Export:`r`n$($_.Exception.Message)", "Export Fehler", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        }
    }
})

# Zwischenablage-Button
$btnCopyToClipboard.Add_Click({
    Write-DebugLog "Kopiere Ergebnisse in Zwischenablage" "UI"
    try {
        # Extrahiere Text aus der RichTextBox
        $textRange = New-Object System.Windows.Documents.TextRange($rtbResults.Document.ContentStart, $rtbResults.Document.ContentEnd)
        $plainText = $textRange.Text
        
        if ([string]::IsNullOrWhiteSpace($plainText)) {
            # Fallback: Erstelle Text aus den Rohdaten
            $allResults = ""
            foreach ($key in $global:auditResults.Keys | Sort-Object) {
                $allResults += "`r`n=== $key ===`r`n$($global:auditResults[$key])`r`n"
            }
            $plainText = $allResults
        }
        
        $plainText | Set-Clipboard
        $txtStatus.Text = "Status: Ergebnisse in Zwischenablage kopiert"
        [System.Windows.MessageBox]::Show("Audit-Ergebnisse wurden in die Zwischenablage kopiert.", "Kopiert", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    } catch {
        [System.Windows.MessageBox]::Show("Fehler beim Kopieren in die Zwischenablage: $($_.Exception.Message)", "Fehler", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
})

# Debug-Funktionen
$btnOpenLog.Add_Click({
    Write-DebugLog "Oeffne Log-Datei" "Debug"
    if (Test-Path $DebugLogPath) {
        Start-Process notepad.exe -ArgumentList $DebugLogPath
    } else {
        [System.Windows.MessageBox]::Show("Log-Datei nicht gefunden.", "Fehler", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
})

$btnClearLog.Add_Click({
    Write-DebugLog "Debug-Log wird geleert" "Debug"
    $script:txtDebugOutput.Text = ""
    if ($DEBUG) {
        $clearMessage = "=== Debug-Log geloescht: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") ==="
        Set-Content -Path $DebugLogPath -Value $clearMessage -Force
        Write-Host $clearMessage -ForegroundColor Cyan
    }
})

Write-DebugLog "UI-Initialisierung abgeschlossen" "Init"

# Funktion zum Formatieren der RichTextBox
function Format-RichTextResults {
    param(
        [hashtable]$Results,
        [string]$CategoryFilter = "Alle"
    )
    
    Write-DebugLog "Formatiere Ergebnisse fuer Kategorie: $CategoryFilter" "UI"
    
    # Erstelle ein neues FlowDocument
    $document = New-Object System.Windows.Documents.FlowDocument
    $document.FontFamily = New-Object System.Windows.Media.FontFamily("Segoe UI")
    $document.FontSize = 12
    $document.LineHeight = 18
    
    # Optimierte Layout-Einstellungen für bessere Textanzeige
    $document.PageWidth = [Double]::NaN  # Unbeschränkte Breite
    $document.PageHeight = [Double]::NaN # Unbeschränkte Höhe
    $document.ColumnWidth = [Double]::PositiveInfinity # Keine Spalten-Begrenzung
    $document.TextAlignment = "Left"
    $document.PagePadding = New-Object System.Windows.Thickness(0)
    $document.IsOptimalParagraphEnabled = $true
    $document.IsHyphenationEnabled = $false
    
    # Gruppiere Ergebnisse nach Kategorien
    $categorizedResults = @{}
    foreach ($cmd in $commands) {
        $category = if ($cmd.Category) { $cmd.Category } else { "Allgemein" }
        if (-not $categorizedResults.ContainsKey($category)) {
            $categorizedResults[$category] = @()
        }
        if ($Results.ContainsKey($cmd.Name)) {
            $categorizedResults[$category] += @{
                Name = $cmd.Name
                Result = $Results[$cmd.Name]
                Command = $cmd
            }
        }
    }
    
    # Bestimme welche Kategorien angezeigt werden sollen
    $categoriesToShow = if ($CategoryFilter -eq "Alle") { 
        $categorizedResults.Keys | Sort-Object 
    } else { 
        @($CategoryFilter) 
    }
    
    $totalItems = 0
    foreach ($category in $categoriesToShow) {
        if ($categorizedResults.ContainsKey($category)) {
            $categoryData = $categorizedResults[$category]
            $totalItems += $categoryData.Count
            
            # Kategorie-Header
            $categoryParagraph = New-Object System.Windows.Documents.Paragraph
            $categoryRun = New-Object System.Windows.Documents.Run("Kategorie: $category")
            $categoryRun.FontWeight = "Bold"
            $categoryRun.FontSize = 16
            $categoryRun.Foreground = New-Object System.Windows.Media.SolidColorBrush([System.Windows.Media.Color]::FromRgb(0, 120, 212))
            $categoryParagraph.Inlines.Add($categoryRun)
            $categoryParagraph.Margin = New-Object System.Windows.Thickness(0, 15, 0, 10)
            $categoryParagraph.TextAlignment = "Left"
            $categoryParagraph.KeepTogether = $true
            $document.Blocks.Add($categoryParagraph)
            
            # Items in dieser Kategorie
            foreach ($item in $categoryData) {
                # Item-Header
                $itemParagraph = New-Object System.Windows.Documents.Paragraph
                $itemRun = New-Object System.Windows.Documents.Run("Eintrag: $($item.Name)")
                $itemRun.FontWeight = "SemiBold"
                $itemRun.FontSize = 13
                $itemRun.Foreground = New-Object System.Windows.Media.SolidColorBrush([System.Windows.Media.Color]::FromRgb(44, 62, 80))
                $itemParagraph.Inlines.Add($itemRun)
                $itemParagraph.Margin = New-Object System.Windows.Thickness(0, 10, 0, 5)
                $itemParagraph.TextAlignment = "Left"
                $itemParagraph.KeepTogether = $true
                $document.Blocks.Add($itemParagraph)
                
                # Kommando-Info (optional)
                if ($item.Command.Command) {
                    $cmdParagraph = New-Object System.Windows.Documents.Paragraph
                    $cmdRun = New-Object System.Windows.Documents.Run("Befehl: $($item.Command.Command)")
                    $cmdRun.FontStyle = "Italic"
                    $cmdRun.FontSize = 10
                    $cmdRun.Foreground = New-Object System.Windows.Media.SolidColorBrush([System.Windows.Media.Color]::FromRgb(108, 117, 125))
                    $cmdParagraph.Inlines.Add($cmdRun)
                    $cmdParagraph.Margin = New-Object System.Windows.Thickness(20, 0, 0, 5)
                    $cmdParagraph.TextAlignment = "Left"
                    $document.Blocks.Add($cmdParagraph)
                }
                
                # Ergebnis in einem optimierten Paragraph für bessere Kontrolle
                $resultParagraph = New-Object System.Windows.Documents.Paragraph
                $resultParagraph.Margin = New-Object System.Windows.Thickness(0, 0, 0, 15)
                $resultParagraph.Padding = New-Object System.Windows.Thickness(15)
                $resultParagraph.Background = New-Object System.Windows.Media.SolidColorBrush([System.Windows.Media.Color]::FromRgb(248, 249, 250))
                $resultParagraph.BorderBrush = New-Object System.Windows.Media.SolidColorBrush([System.Windows.Media.Color]::FromRgb(222, 226, 230))
                $resultParagraph.BorderThickness = New-Object System.Windows.Thickness(1)
                $resultParagraph.TextAlignment = "Left"
                
                # Optimierte Textbehandlung - einfacher und robuster
                $resultText = $item.Result
                if ([string]::IsNullOrWhiteSpace($resultText)) {
                    $resultText = "Keine Daten verfügbar"
                }
                
                # Verwende einen einzigen Run für den gesamten Text
                $resultRun = New-Object System.Windows.Documents.Run($resultText)
                $resultRun.FontFamily = New-Object System.Windows.Media.FontFamily("Consolas")
                $resultRun.FontSize = 11
                $resultParagraph.Inlines.Add($resultRun)
                
                $document.Blocks.Add($resultParagraph)
            }
        }
    }
    
    # Update Summary
    $window.Dispatcher.Invoke([Action]{
        $txtResultsSummary.Text = "Zeige $totalItems Einträge"
    }, "Normal")
    
    return $document
}

# Funktion zum Aktualisieren der Kategorien-ComboBox
function Update-ResultsCategories {
    Write-DebugLog "Aktualisiere Kategorien-ComboBox" "UI"
    
    $cmbResultCategories.Items.Clear()
    
    # "Alle" Option hinzufügen
    $allItem = New-Object System.Windows.Controls.ComboBoxItem
    $allItem.Content = "Alle Kategorien" # Emoji entfernt
    $allItem.Tag = "Alle"
    $cmbResultCategories.Items.Add($allItem)
    
    # Einzelne Kategorien hinzufügen
    # $commands wird als global/script-scoped Variable angenommen
    $categories = @{}
    if ($null -ne $commands) {
        foreach ($cmd in $commands) {
            $category = if ($cmd.Category) { $cmd.Category } else { "Allgemein" }
            if (-not $categories.ContainsKey($category)) {
                $categories[$category] = 0
            }
            if ($global:auditResults.ContainsKey($cmd.Name)) {
                $categories[$category]++
            }
        }
    }
    
    foreach ($category in $categories.Keys | Sort-Object) {
        if ($categories[$category] -gt 0) {
            $categoryItem = New-Object System.Windows.Controls.ComboBoxItem
            $categoryItem.Content = "$category ($($categories[$category]))" # Emoji entfernt
            $categoryItem.Tag = $category
            $cmbResultCategories.Items.Add($categoryItem)
        }
    }
    
    # Ersten Eintrag auswählen
    if ($cmbResultCategories.Items.Count -gt 0) {
        $cmbResultCategories.SelectedIndex = 0
    }
}

# Funktion zum Anzeigen der Ergebnisse
function Show-CategoryResults {
    param([string]$Category = "Alle")
    
    Write-DebugLog "Zeige Ergebnisse fuer Kategorie: $Category" "UI"
    
    if ($global:auditResults.Count -eq 0) {
        $rtbResults.Document = New-Object System.Windows.Documents.FlowDocument
        $emptyParagraph = New-Object System.Windows.Documents.Paragraph
        $emptyRun = New-Object System.Windows.Documents.Run("Keine Audit-Ergebnisse verfügbar. Führen Sie zuerst ein Audit durch.")
        $emptyRun.FontStyle = "Italic"
        $emptyRun.Foreground = New-Object System.Windows.Media.SolidColorBrush([System.Windows.Media.Color]::FromRgb(108, 117, 125))
        $emptyParagraph.Inlines.Add($emptyRun)
        $rtbResults.Document.Blocks.Add($emptyParagraph)
        return
    }
    
    try {
        # Versuche die formatierte Anzeige
        $document = Format-RichTextResults -Results $global:auditResults -CategoryFilter $Category
        $rtbResults.Document = $document
        
        # Erzwinge Layout-Update
        $rtbResults.UpdateLayout()
        
        Write-DebugLog "Ergebnisse erfolgreich formatiert und angezeigt" "UI"
    }
    catch {
        Write-DebugLog "FEHLER bei der formatierten Anzeige: $($_.Exception.Message) - Verwende Fallback" "UI"
        
        # Fallback: Verwende einfache Textanzeige
        Show-SimpleResults -Category $Category
    }
}

# Fallback-Funktion für einfache Textanzeige
function Show-SimpleResults {
    param([string]$Category = "Alle")
    
    Write-DebugLog "Verwende einfache Textanzeige für Kategorie: $Category" "UI"
    
    # Erstelle einfaches FlowDocument
    $document = New-Object System.Windows.Documents.FlowDocument
    $document.FontFamily = New-Object System.Windows.Media.FontFamily("Consolas")
    $document.FontSize = 11
    $document.PageWidth = [Double]::NaN
    $document.PageHeight = [Double]::NaN
    $document.ColumnWidth = [Double]::PositiveInfinity
    
    # Sammle alle relevanten Ergebnisse als einfachen Text
    $resultText = ""
    
    # Gruppiere nach Kategorien
    $categorizedResults = @{}
    foreach ($cmd in $commands) {
        $cmdCategory = if ($cmd.Category) { $cmd.Category } else { "Allgemein" }
        if (-not $categorizedResults.ContainsKey($cmdCategory)) {
            $categorizedResults[$cmdCategory] = @()
        }
        if ($global:auditResults.ContainsKey($cmd.Name)) {
            $categorizedResults[$cmdCategory] += @{
                Name = $cmd.Name
                Result = $global:auditResults[$cmd.Name]
            }
        }
    }
    
    # Bestimme anzuzeigende Kategorien
    $categoriesToShow = if ($Category -eq "Alle") { 
        $categorizedResults.Keys | Sort-Object 
    } else { 
        @($Category) 
    }
    
    $totalItems = 0
    foreach ($cat in $categoriesToShow) {
        if ($categorizedResults.ContainsKey($cat)) {
            $categoryData = $categorizedResults[$cat]
            $totalItems += $categoryData.Count
            
            $resultText += "`n" + "="*60 + "`n"
            $resultText += "KATEGORIE: $cat`n"
            $resultText += "="*60 + "`n`n"
            
            foreach ($item in $categoryData) {
                $resultText += "-"*40 + "`n"
                $resultText += "EINTRAG: $($item.Name)`n"
                $resultText += "-"*40 + "`n"
                $resultText += "$($item.Result)`n`n"
            }
        }
    }
    
    # Erstelle einfachen Paragraph mit dem gesamten Text
    $paragraph = New-Object System.Windows.Documents.Paragraph
    $run = New-Object System.Windows.Documents.Run($resultText)
    $paragraph.Inlines.Add($run)
    $document.Blocks.Add($paragraph)
    
    $rtbResults.Document = $document
    
    # Update Summary
    $window.Dispatcher.Invoke([Action]{
        $txtResultsSummary.Text = "Zeige $totalItems Einträge (einfache Ansicht)"
    }, "Normal")
}

# Initialisiere die Ergebnisse-Anzeige
Show-CategoryResults -Category "Alle"

# Optimiere die RichTextBox für besseres Text-Wrapping
Optimize-RichTextBoxLayout

# Initialisiere die Ergebnisse-Anzeige
Show-CategoryResults -Category "Alle"

# Verbindungsaudit Export-Button-Funktionalitaet
$btnExportConnectionHTML.Add_Click({
    Write-DebugLog "Verbindungsaudit HTML-Export gestartet" "Export"
    
    $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveFileDialog.Filter = "HTML Files (*.html)|*.html"
    $saveFileDialog.Title = "Speichern Sie den Verbindungsaudit-Bericht"
    $saveFileDialog.FileName = "ConnectionAudit_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    
    if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $txtStatus.Text = "Status: Exportiere Verbindungsaudit-HTML..."
        
        try {
            Export-ConnectionAuditToHTML -Results $global:connectionAuditResults -FilePath $saveFileDialog.FileName
            $txtStatus.Text = "Status: Verbindungsaudit-Export erfolgreich abgeschlossen"
            [System.Windows.MessageBox]::Show("Verbindungsaudit-Bericht wurde erfolgreich exportiert:`r`n$($saveFileDialog.FileName)", "Export erfolgreich", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        } catch {
            $txtStatus.Text = "Status: Fehler beim Verbindungsaudit-Export"
            [System.Windows.MessageBox]::Show("Fehler beim Export:`r`n$($_.Exception.Message)", "Export Fehler", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        }
    }
})

# Verbindungsaudit Zwischenablage-Button
$btnCopyConnectionToClipboard.Add_Click({
    Write-DebugLog "Kopiere Verbindungsaudit-Ergebnisse in Zwischenablage" "UI"
    try {
        # Extrahiere Text aus der RichTextBox
        $textRange = New-Object System.Windows.Documents.TextRange($rtbConnectionResults.Document.ContentStart, $rtbConnectionResults.Document.ContentEnd)
        $plainText = $textRange.Text
        
        if ([string]::IsNullOrWhiteSpace($plainText)) {
            # Fallback: Erstelle Text aus den Rohdaten
            $allResults = ""
            foreach ($key in $global:connectionAuditResults.Keys | Sort-Object) {
                $allResults += "`r`n=== $key ===`r`n$($global:connectionAuditResults[$key])`r`n"
            }
            $plainText = $allResults
        }
        
        $plainText | Set-Clipboard
        $txtStatus.Text = "Status: Verbindungsaudit-Ergebnisse in Zwischenablage kopiert"
        [System.Windows.MessageBox]::Show("Verbindungsaudit-Ergebnisse wurden in die Zwischenablage kopiert.", "Kopiert", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    } catch {
        [System.Windows.MessageBox]::Show("Fehler beim Kopieren in die Zwischenablage: $($_.Exception.Message)", "Fehler", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
})

# Verbindungsaudit ComboBox Selection Changed Event
$cmbConnectionCategories.Add_SelectionChanged({
    if ($cmbConnectionCategories.SelectedItem) {
        $selectedCategory = $cmbConnectionCategories.SelectedItem.Tag
        Show-ConnectionCategoryResults -Category $selectedCategory
    }
})

# Initialisiere die Verbindungsaudit-Ergebnisse-Anzeige
Show-ConnectionCategoryResults -Category "Alle"

# Initialisiere die Ergebnisse-Anzeige
Show-CategoryResults -Category "Alle"

# Funktion zum Bereinigen von Sonderzeichen, Umlauten und Symbolen
function Clean-StringForDiagram {
    param(
        [string]$InputString
    )
    
    if ([string]::IsNullOrWhiteSpace($InputString)) {
        return "Unbekannt"
    }
    
    # Umlaute und Sonderzeichen ersetzen
    $cleanString = $InputString -replace 'ä', 'ae' -replace 'ö', 'oe' -replace 'ü', 'ue' -replace 'Ä', 'Ae' -replace 'Ö', 'Oe' -replace 'Ü', 'Ue' -replace 'ß', 'ss'
    
    # Sonderzeichen und Symbole entfernen oder ersetzen
    $cleanString = $cleanString -replace '[^\w\s\.\-_:]', '' -replace '\s+', ' '
    $cleanString = $cleanString.Trim()
    
    # XML-sichere Zeichen
    $cleanString = $cleanString -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&apos;'
    
    if ([string]::IsNullOrWhiteSpace($cleanString)) {
        return "Bereinigt"
    }
    
    return $cleanString
}

# Funktion zum Erstellen eines DRAW.IO XML Exports der Netzwerk-Topologie
function Export-NetworkTopologyToDrawIO {
    param(
        [hashtable]$Results,
        [string]$FilePath,
        [string]$ServerName = $env:COMPUTERNAME
    )
    
    Write-DebugLog "Starte DRAW.IO Netzwerk-Topologie Export nach: $FilePath" "DrawIO-Export"
    
    try {
        $cleanServerName = Clean-StringForDiagram -InputString $ServerName
        
        # --- Datenextraktion und -verarbeitung ---
        $processedData = @{
            TCPConnections = @()
            NetworkAdapters = @() # Wird unten neu befüllt
            ListeningPorts = @()
            ExternalConnections = @()
            GatewayIP = "N/A"
            DnsServers = "N/A"
            PrimaryIP = "IP nicht ermittelt"
            ServerOS = "Windows Server" # Generisch, da OS-Info nicht direkt in $Results erwartet wird
        }

        # TCP Verbindungen verarbeiten (für Statistiken und ggf. IP-Ermittlung)
        if ($Results.ContainsKey("Alle TCP-Verbindungen (Performance)") -or $Results.ContainsKey("Etablierte TCP-Verbindungen")) {
            $tcpData = $Results["Alle TCP-Verbindungen (Performance)"]
            if (-not $tcpData) { $tcpData = $Results["Etablierte TCP-Verbindungen"] }
            if ($tcpData) {
                $tcpLines = $tcpData -split "`n" | Where-Object { $_ -match '\d+\.\d+\.\d+\.\d+' }
                foreach ($line in $tcpLines) {
                    if ($line -match '(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\w+)') {
                        $processedData.TCPConnections += @{
                            LocalIP = $matches[1]; LocalPort = $matches[2]; RemoteIP = $matches[3]; RemotePort = $matches[4]; State = $matches[5]
                        }
                    }
                }
            }
        }

        # Netzwerkadapter-Daten detaillierter parsen
        $parsedAdapters = @()
        $adapterDataSource = $null
        if ($Results.ContainsKey("Erweiterte Netzwerk-Adapter-Infos")) { $adapterDataSource = $Results["Erweiterte Netzwerk-Adapter-Infos"] }
        elseif ($Results.ContainsKey("Netzwerkadapter")) { $adapterDataSource = $Results["Netzwerkadapter"] }

        if ($adapterDataSource) {
            $currentAdapter = $null
            $adapterLines = $adapterDataSource -split '\r?\n'
            foreach ($line in $adapterLines) {
                if ($line -match '^(Name|InterfaceAlias)\s*:\s*(.+)$' -or $line -match '^\s*Beschreibung\.+:\s*(.+)$') { # Deutsch: Beschreibung
                    if ($currentAdapter) { $parsedAdapters += $currentAdapter }
                    $currentAdapter = @{ Name = Clean-StringForDiagram ($matches[1]).Trim(); Status = "Unknown"; Description = ""; IPAddress = "N/A"; SubnetMask = "N/A" }
                    if ($line -match '^(Name|InterfaceAlias)\s*:\s*(.+)$') { $currentAdapter.Name = Clean-StringForDiagram ($matches[2]).Trim() }
                    else { $currentAdapter.Description = Clean-StringForDiagram ($matches[1]).Trim() } # Fallback für Name wenn nur Beschreibung da
                } elseif ($currentAdapter) {
                    if ($line -match '^\s*(Status|Status der Verbindung)\s*:\s*(.+)$') { $currentAdapter.Status = Clean-StringForDiagram ($matches[2]).Trim() } # Deutsch: Status der Verbindung
                    elseif ($line -match '^\s*(InterfaceDescription|Beschreibung)\s*:\s*(.+)$') { $currentAdapter.Description = Clean-StringForDiagram ($matches[2]).Trim() }
                    elseif ($line -match '^\s*IPv4-Adresse\.+:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*') { # Deutsch: IPv4-Adresse
                         if ($matches[1] -ne "0.0.0.0") { $currentAdapter.IPAddress = $matches[1] }
                    } elseif ($line -match '^\s*IPv4Address\s*:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') { # Englisch
                         if ($matches[1] -ne "0.0.0.0") { $currentAdapter.IPAddress = $matches[1] }
                    } elseif ($line -match '^\s*Subnetzmaske\.+:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') { # Deutsch
                        $currentAdapter.SubnetMask = $matches[1]
                    } elseif ($line -match '^\s*SubnetMask\s*:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') { # Englisch
                        $currentAdapter.SubnetMask = $matches[1]
                    }
                }
            }
            if ($currentAdapter) { $parsedAdapters += $currentAdapter }
            $processedData.NetworkAdapters = $parsedAdapters | Where-Object { -not ([string]::IsNullOrWhiteSpace($_.Name)) }
        }
        
        # Primäre IP-Adresse ermitteln
        $activeAdapterWithIP = $processedData.NetworkAdapters | Where-Object { ($_.Status -eq "Up" -or $_.Status -eq "Aktiviert") -and $_.IPAddress -ne "N/A" -and $_.IPAddress -ne "0.0.0.0" -and $_.IPAddress -notmatch "^169\.254\." -and $_.IPAddress -ne "127.0.0.1"} | Select-Object -First 1
        if ($activeAdapterWithIP) {
            $processedData.PrimaryIP = $activeAdapterWithIP.IPAddress
        } elseif ($processedData.TCPConnections.Count -gt 0) {
            $firstLocalTCP_IP = ($processedData.TCPConnections | Where-Object {$_.LocalIP -ne "0.0.0.0" -and $_.LocalIP -ne "127.0.0.1"} | Select-Object -First 1).LocalIP
            if ($firstLocalTCP_IP) { $processedData.PrimaryIP = $firstLocalTCP_IP }
        }


        # Gateway IP ermitteln
        if ($Results.ContainsKey("Netzwerkkonfiguration (ipconfig)")) {
            $ipConfigData = $Results["Netzwerkkonfiguration (ipconfig)"]
            if ($ipConfigData -match '(Standardgateway|Default Gateway).+:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') {
                if ($matches[2] -ne "0.0.0.0") { $processedData.GatewayIP = $matches[2] }
            }
        } elseif ($Results.ContainsKey("Routing Tabelle")) {
            $routingData = $Results["Routing Tabelle"]
            $routeLines = $routingData -split "`n" | Where-Object { $_ -match '^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' }
            if ($routeLines.Count -gt 0) {
                # $matches is not available outside the Where-Object script block in this context directly
                # Need to re-match or extract differently
                $gwMatch = $routeLines[0] | Select-String -Pattern '^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
                if ($gwMatch) { $processedData.GatewayIP = $gwMatch.Matches[0].Groups[1].Value }
            }
        }
         if ([string]::IsNullOrWhiteSpace($processedData.GatewayIP) -or $processedData.GatewayIP -match "0.0.0.0") { $processedData.GatewayIP = "N/A" }


        # DNS Server ermitteln
        if ($Results.ContainsKey("Netzwerkkonfiguration (ipconfig)")) {
            $ipConfigData = $Results["Netzwerkkonfiguration (ipconfig)"]
            $dnsMatches = $ipConfigData | Select-String -Pattern '(DNS-Server|DNS Servers).+:\s*((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*)+)' -AllMatches
            if ($dnsMatches) {
                $dnsIPs = $dnsMatches.Matches.Groups[2].Value -split '\s+' | Where-Object {$_ -match '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'} | Get-Unique
                if ($dnsIPs.Count -gt 0) { $processedData.DnsServers = $dnsIPs -join ', ' }
            }
        }
        if ([string]::IsNullOrWhiteSpace($processedData.DnsServers)) { $processedData.DnsServers = "N/A" }

        # Lauschende Ports verarbeiten
        if ($Results.ContainsKey("Lauschende Ports (Listen)")) {
            $listenData = $Results["Lauschende Ports (Listen)"]
            if ($listenData) {
                $listenLines = $listenData -split "`n" | Where-Object { $_ -match '(\d+\.\d+\.\d+\.\d+|\[::\]|0\.0\.0\.0)\s*:\s*(\d+)' } # Adjusted regex for IP:Port format
                foreach ($line in $listenLines) {
                     if ($line -match '(\d+\.\d+\.\d+\.\d+|\[::\]|0\.0\.0\.0)\s*:\s*(\d+)') { # More specific for IP:Port
                        $processedData.ListeningPorts += @{ IP = $matches[1]; Port = $matches[2] }
                    } elseif ($line -match '(\S+)\s+(\d+)\s+LISTENING') { # Fallback for netstat like format if IP:Port fails
                        $processedData.ListeningPorts += @{ IP = $matches[1]; Port = $matches[2] }
                    }
                }
            }
        }
        
        # Externe Verbindungen verarbeiten
        if ($Results.ContainsKey("Externe Verbindungen (Internet)")) {
            $externalData = $Results["Externe Verbindungen (Internet)"]
            if ($externalData) {
                $externalLines = $externalData -split "`n" | Where-Object { $_ -match '\d+\.\d+\.\d+\.\d+' }
                foreach ($line in $externalLines) {
                    if ($line -match '(\d+\.\d+\.\d+\.\d+)\s*:\s*(\d+)\s+(\d+\.\d+\.\d+\.\d+)\s*:\s*(\d+)') { # Adjusted for IP:Port format
                        $processedData.ExternalConnections += @{ LocalIP = $matches[1]; LocalPort = $matches[2]; RemoteIP = $matches[3]; RemotePort = $matches[4] }
                    }
                }
            }
        }

        # --- XML Generierung ---
        $cellIdCounter = 10 # Start counter for unique IDs

        # XML Header
        $xmlContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<mxfile host="Electron" agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) draw.io/27.0.5 Chrome/134.0.6998.205 Electron/35.3.0 Safari/537.36" version="27.0.5">
  <diagram name="Netzwerk-Topologie $(Clean-StringForDiagram $ServerName)" id="$(New-Guid)">
    <mxGraphModel dx="1700" dy="1000" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="1169" pageHeight="827" math="0" shadow="0">
      <root>
        <mxCell id="0" />
        <mxCell id="1" parent="0" />
"@
        # Zentraler Server
        $serverValue = "Hostname: $cleanServerName&#xa;IP: $(Clean-StringForDiagram $processedData.PrimaryIP)&#xa;OS: $(Clean-StringForDiagram $processedData.ServerOS)"
        $xmlContent += @"
        <!-- Zentraler Server -->
        <mxCell id="server-central" value="$serverValue" style="shape=mxgraph.windows.server;html=1;whiteSpace=wrap;fontSize=12;fontStyle=1;fillColor=#dae8fc;strokeColor=#6c8ebf;strokeWidth=2;" vertex="1" parent="1">
          <mxGeometry x="750" y="450" width="180" height="100" as="geometry" />
        </mxCell>
"@
        # Gateway
        $gatewayValue = "Gateway&#xa;IP: $(Clean-StringForDiagram $processedData.GatewayIP)"
        $xmlContent += @"
        <!-- Gateway -->
        <mxCell id="gateway-node" value="$gatewayValue" style="shape=mxgraph.cisco.routers.router_with_firewall_symbol;html=1;whiteSpace=wrap;fontSize=10;fillColor=#f8cecc;strokeColor=#b85450;" vertex="1" parent="1">
          <mxGeometry x="780" y="100" width="120" height="70" as="geometry" />
        </mxCell>
        <mxCell id="edge-server-gateway" style="edgeStyle=orthogonalEdgeStyle;rounded=0;orthogonalLoop=1;jettySize=auto;html=1;strokeColor=#000000;strokeWidth=1;" edge="1" parent="1" source="server-central" target="gateway-node">
          <mxGeometry relative="1" as="geometry" />
        </mxCell>
"@
        # DNS Server
        $dnsValue = "DNS Server&#xa;$(Clean-StringForDiagram $processedData.DnsServers)"
        $xmlContent += @"
        <!-- DNS Server -->
        <mxCell id="dns-node" value="$dnsValue" style="shape=mxgraph.cisco.servers.dns_server;html=1;whiteSpace=wrap;fontSize=10;fillColor=#fff2cc;strokeColor=#d6b656;" vertex="1" parent="1">
          <mxGeometry x="1050" y="250" width="140" height="80" as="geometry" />
        </mxCell>
        <mxCell id="edge-server-dns" style="edgeStyle=orthogonalEdgeStyle;rounded=0;orthogonalLoop=1;jettySize=auto;html=1;strokeColor=#000000;strokeWidth=1;" edge="1" parent="1" source="server-central" target="dns-node">
          <mxGeometry relative="1" as="geometry" />
        </mxCell>
"@
        # NAS/SAN (Placeholder)
        $xmlContent += @"
        <!-- NAS/SAN -->
        <mxCell id="nas-node" value="NAS / SAN&#xa;(Details manuell eintragen)" style="shape=mxgraph.cisco.storage.nas_icon;html=1;whiteSpace=wrap;fontSize=10;fillColor=#e1d5e7;strokeColor=#9673a6;" vertex="1" parent="1">
          <mxGeometry x="450" y="250" width="140" height="80" as="geometry" />
        </mxCell>
        <mxCell id="edge-server-nas" style="edgeStyle=orthogonalEdgeStyle;rounded=0;orthogonalLoop=1;jettySize=auto;html=1;strokeColor=#000000;strokeWidth=1;" edge="1" parent="1" source="server-central" target="nas-node">
          <mxGeometry relative="1" as="geometry" />
        </mxCell>
"@
        # Internet Cloud (für externe Verbindungen)
        $xmlContent += @"
        <!-- Internet Cloud -->
        <mxCell id="internet-cloud" value="Internet" style="shape=cloud;html=1;whiteSpace=wrap;fontSize=12;fillColor=#f5f5f5;strokeColor=#666666;" vertex="1" parent="1">
          <mxGeometry x="780" y="750" width="120" height="80" as="geometry" />
        </mxCell>
        <mxCell id="edge-gateway-internet" style="edgeStyle=orthogonalEdgeStyle;rounded=0;orthogonalLoop=1;jettySize=auto;html=1;strokeColor=#000000;strokeWidth=1;" edge="1" parent="1" source="gateway-node" target="internet-cloud">
          <mxGeometry relative="1" as="geometry" />
        </mxCell>
"@
        # Netzwerkadapter (als NETWORK / NETWORK2 etc.)
        $adapterXStart = 100
        $adapterY = 480
        $adapterCount = 0
        foreach ($adapter in ($processedData.NetworkAdapters | Where-Object {$_.Status -ne "Disabled" -and $_.Status -ne "Deaktiviert"} | Select-Object -First 3)) {
            $cellIdCounter++
            $adapterNameClean = Clean-StringForDiagram $adapter.Name
            $adapterIpClean = Clean-StringForDiagram $adapter.IPAddress
            $adapterSubnetClean = Clean-StringForDiagram $adapter.SubnetMask
            $adapterStatusClean = Clean-StringForDiagram $adapter.Status
            
            $adapterLabel = "Adapter: $adapterNameClean&#xa;IP: $adapterIpClean&#xa;Subnetz: $adapterSubnetClean&#xa;Status: $adapterStatusClean"
            $fillColor = if ($adapter.Status -eq "Up" -or $adapter.Status -eq "Aktiviert") { "#d5e8d4" } else { "#f8cecc" } # Grün für Up, Rot für Down
            $strokeColor = if ($adapter.Status -eq "Up" -or $adapter.Status -eq "Aktiviert") { "#82b366" } else { "#b85450" }

            $xmlContent += @"
        <!-- Netzwerkadapter: $adapterNameClean -->
        <mxCell id="adapter-$cellIdCounter" value="$adapterLabel" style="shape=card;html=1;whiteSpace=wrap;fontSize=9;fillColor=$fillColor;strokeColor=$strokeColor;" vertex="1" parent="1">
          <mxGeometry x="$($adapterXStart + ($adapterCount * 200))" y="$adapterY" width="160" height="90" as="geometry" />
        </mxCell>
        <mxCell id="edge-server-adapter-$cellIdCounter" style="edgeStyle=orthogonalEdgeStyle;rounded=0;orthogonalLoop=1;jettySize=auto;html=1;strokeColor=#000000;strokeWidth=1;" edge="1" parent="1" source="server-central" target="adapter-$cellIdCounter">
          <mxGeometry relative="1" as="geometry" />
        </mxCell>
"@
            $adapterCount++
        }

        # Lauschende Ports (als kleine verbundene Elemente)
        $listenPortXStart = 1050
        $listenPortYStart = 400
        $listenPortMax = 25
        $listenPortCurrent = 0
        $uniqueListeningPorts = $processedData.ListeningPorts | Sort-Object Port -Unique | Select-Object -First $listenPortMax
        
        foreach ($portInfo in $uniqueListeningPorts) {
            $cellIdCounter++
            $portClean = Clean-StringForDiagram $portInfo.Port
            $portLabel = "Port: $portClean"
            
            $xmlContent += @"
        <!-- Lauschender Port: $portClean -->
        <mxCell id="lport-$cellIdCounter" value="$portLabel" style="ellipse;shape=doubleEllipse;html=1;whiteSpace=wrap;fontSize=9;fillColor=#dae8fc;strokeColor=#6c8ebf;perimeter=ellipsePerimeter;" vertex="1" parent="1">
          <mxGeometry x="$($listenPortXStart + ($listenPortCurrent % 2 * 70))" y="$($listenPortYStart + ([Math]::Floor($listenPortCurrent / 2) * 50))" width="60" height="40" as="geometry" />
        </mxCell>
        <mxCell id="edge-server-lport-$cellIdCounter" style="edgeStyle=orthogonalEdgeStyle;rounded=0;orthogonalLoop=1;jettySize=auto;html=1;strokeColor=#6c8ebf;strokeWidth=1;endArrow=none;" edge="1" parent="1" source="server-central" target="lport-$cellIdCounter">
          <mxGeometry relative="1" as="geometry" />
        </mxCell>
"@
            $listenPortCurrent++
        }

        # Externe Verbindungen (gruppiert nach Remote IP)
        $extConnXStart = 450
        $extConnYStart = 700 
        $extConnMaxGroups = 3
        $extConnGroups = $processedData.ExternalConnections | Group-Object RemoteIP | Select-Object -First $extConnMaxGroups
        $extConnCounter = 0

        foreach ($group in $extConnGroups) {
            $cellIdCounter++
            $remoteIpClean = Clean-StringForDiagram $group.Name
            $ports = ($group.Group | Select-Object -ExpandProperty RemotePort -Unique | Select-Object -First 3) -join ", "
            if (($group.Group | Select-Object -ExpandProperty RemotePort -Unique).Count -gt 3) { $ports += ", ..." }
            $extConnLabel = "Extern: $remoteIpClean&#xa;Ports: $ports"

            $xmlContent += @"
        <!-- Externe Verbindung: $remoteIpClean -->
        <mxCell id="extconn-$cellIdCounter" value="$extConnLabel" style="rounded=0;whiteSpace=wrap;html=1;fontSize=9;fillColor=#fad7ac;strokeColor=#b46504;" vertex="1" parent="1">
          <mxGeometry x="$($extConnXStart + ($extConnCounter * 130))" y="$($extConnYStart - 100)" width="120" height="60" as="geometry" />
        </mxCell>
        <mxCell id="edge-server-extconn-$cellIdCounter" style="edgeStyle=orthogonalEdgeStyle;rounded=0;orthogonalLoop=1;jettySize=auto;html=1;strokeColor=#b46504;strokeWidth=1;dashed=1;" edge="1" parent="1" source="server-central" target="extconn-$cellIdCounter">
          <mxGeometry relative="1" as="geometry" />
        </mxCell>
        <mxCell id="edge-extconn-internet-$cellIdCounter" style="edgeStyle=orthogonalEdgeStyle;rounded=0;orthogonalLoop=1;jettySize=auto;html=1;strokeColor=#b46504;strokeWidth=1;dashed=1;" edge="1" parent="1" source="extconn-$cellIdCounter" target="internet-cloud">
          <mxGeometry relative="1" as="geometry" />
        </mxCell>
"@
            $extConnCounter++
        }
        
        # Legende und Statistiken
        $statsLabel = "Statistiken&#xa;TCP Gesamt: $($processedData.TCPConnections.Count)&#xa;Externe Verb.: $($processedData.ExternalConnections.Count)&#xa;Lauschende Ports: $($processedData.ListeningPorts.Count)"
        $xmlContent += @"
        <!-- Statistiken -->
        <mxCell id="stats-node" value="$statsLabel" style="text;html=1;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;whiteSpace=wrap;rounded=0;fontSize=10;fontStyle=0;" vertex="1" parent="1">
          <mxGeometry x="50" y="50" width="180" height="70" as="geometry" />
        </mxCell>
        
        <!-- Legende -->
        <mxCell id="legend-title" value="Legende" style="text;html=1;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;whiteSpace=wrap;rounded=0;fontSize=12;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="50" y="130" width="150" height="20" as="geometry" />
        </mxCell>
        <mxCell id="legend-server" value="Zentraler Server" style="shape=mxgraph.windows.server;html=1;fontSize=9;fillColor=#dae8fc;strokeColor=#6c8ebf;" vertex="1" parent="1">
          <mxGeometry x="50" y="160" width="120" height="30" as="geometry" />
        </mxCell>
        <mxCell id="legend-gateway" value="Gateway" style="shape=mxgraph.cisco.routers.router_with_firewall_symbol;html=1;fontSize=9;fillColor=#f8cecc;strokeColor=#b85450;" vertex="1" parent="1">
          <mxGeometry x="50" y="200" width="120" height="30" as="geometry" />
        </mxCell>
        <mxCell id="legend-dns" value="DNS Server" style="shape=mxgraph.cisco.servers.dns_server;html=1;fontSize=9;fillColor=#fff2cc;strokeColor=#d6b656;" vertex="1" parent="1">
          <mxGeometry x="50" y="240" width="120" height="30" as="geometry" />
        </mxCell>
        <mxCell id="legend-adapter" value="Netzwerkadapter" style="shape=card;html=1;fontSize=9;fillColor=#d5e8d4;strokeColor=#82b366;" vertex="1" parent="1">
          <mxGeometry x="50" y="280" width="120" height="30" as="geometry" />
        </mxCell>
        <mxCell id="legend-lport" value="Lauschender Port" style="ellipse;shape=doubleEllipse;html=1;fontSize=9;fillColor=#dae8fc;strokeColor=#6c8ebf;" vertex="1" parent="1">
          <mxGeometry x="50" y="320" width="120" height="30" as="geometry" />
        </mxCell>
        <mxCell id="legend-extconn" value="Externe Verbindung" style="rounded=0;html=1;fontSize=9;fillColor=#fad7ac;strokeColor=#b46504;" vertex="1" parent="1">
          <mxGeometry x="50" y="360" width="120" height="30" as="geometry" />
        </mxCell>
"@

        # XML Footer
        $xmlContent += @"
      </root>
    </mxGraphModel>
  </diagram>
</mxfile>
"@
        
        # Datei schreiben
        $xmlContent | Out-File -FilePath $FilePath -Encoding UTF8 -Force
        
        Write-DebugLog "DRAW.IO Netzwerk-Topologie Export erfolgreich abgeschlossen" "DrawIO-Export"
        Write-DebugLog "Verarbeitete TCP-Verbindungen: $($processedData.TCPConnections.Count)" "DrawIO-Export"
        
        return $true
    }
    catch {
        Write-DebugLog "FEHLER beim DRAW.IO Export: $($_.Exception.Message)" "DrawIO-Export"
        Write-DebugLog "Stack Trace: $($_.ScriptStackTrace)" "DrawIO-Export"
        throw # Re-throw original exception to preserve details
    }
}

# Verbindungsaudit DRAW.IO Export-Button-Funktionalitaet
$btnExportConnectionDrawIO.Add_Click({
    Write-DebugLog "Verbindungsaudit DRAW.IO-Export gestartet" "Export"
    
    if ($global:connectionAuditResults.Count -eq 0) {
        [System.Windows.MessageBox]::Show("Keine Verbindungsaudit-Ergebnisse zum Exportieren vorhanden.", "Keine Daten", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }
    
    $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveFileDialog.Filter = "DRAW.IO XML Files (*.xml)|*.xml"
    $saveFileDialog.Title = "Speichern Sie die Netzwerk-Topologie"
    $saveFileDialog.FileName = "ConnectionTopology_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"
    
    if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $txtProgressConnection.Text = "Exportiere Netzwerk-Topologie..."
        
        try {
            Export-NetworkTopologyToDrawIO -Results $global:connectionAuditResults -FilePath $saveFileDialog.FileName -ServerName $env:COMPUTERNAME
            $txtProgressConnection.Text = "DRAW.IO-Export erfolgreich abgeschlossen"
            [System.Windows.MessageBox]::Show("Netzwerk-Topologie wurde erfolgreich exportiert:`r`n$($saveFileDialog.FileName)", "Export erfolgreich", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        } catch {
            $txtProgressConnection.Text = "Fehler beim DRAW.IO-Export"
            [System.Windows.MessageBox]::Show("Fehler beim DRAW.IO-Export:`r`n$($_.Exception.Message)", "Export Fehler", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        }
    }
})

# Initialisiere die Ergebnisse-Anzeige
Show-CategoryResults -Category "Alle"
Write-DebugLog "GUI initialisiert, warte auf Benutzerinteraktion" "Startup"

# Zeige das Fenster an
$txtStatus.Text = "Status: Bereit fuer Audit"
Write-DebugLog "Zeige Hauptfenster" "UI"
$null = $window.ShowDialog()
Write-DebugLog "Anwendung geschlossen" "Shutdown"
