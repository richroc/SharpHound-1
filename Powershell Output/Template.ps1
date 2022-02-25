function Invoke-BloodHound{
    <#
    .SYNOPSIS

        Runs the BloodHound C# Ingestor using reflection. The assembly is stored in this file.
        Updated to work with Sharphound v1.0.2

    .DESCRIPTION

        Using reflection and assembly.load, load the compiled BloodHound C# ingestor into memory
        and run it without touching disk. Parameters are converted to the equivalent CLI arguments
        for the SharpHound executable and passed in via reflection. The appropriate function
        calls are made in order to ensure that assembly dependencies are loaded properly.

    .PARAMETER CollectionMethods

        Specifies the CollectionMethod being used. Possible value are:
			Container
			Group
			LocalGroup
			GPOLocalGroup
            		Session
			LoggedOn
			ObjectProps
			ACL
			ComputerOnly
			Trusts
			Default
			RDP
			DCOM
			DCOnly

        This can be a list of comma seperated valued as well to run multiple collection methods!
    
	.PARAMETER Domain

        Specifies the domain to enumerate. If not specified, will enumerate the current
        domain your user context specifies.
	
	.PARAMETER SearchForest
		 (Default: false) Search all available domains in the forest
		
    .PARAMETER Stealth

        Use stealth collection options, will sacrifice data quality in favor of much reduced
        network impact
	
	.PARAMETER f                        
		Add an LDAP filter to the pregenerated filter.

	.PARAMETER distinguishedname        
		Base DistinguishedName to start the LDAP search at

	.PARAMETER computerfile             
		Path to file containing computer names to enumerate

	.PARAMETER outputdirectory          
		(Default: .) Directory to output file too

	.PARAMETER outputprefix             
		String to prepend to output file names

	.PARAMETER cachename                
		Filename for cache (Defaults to a machine specific identifier)

	.PARAMETER memcache                 
		Keep cache in memory and don't write to disk

	.PARAMETER rebuildcache             
		(Default: false) Rebuild cache and remove all entries

	.PARAMETER randomfilenames          
		(Default: false) Use random filenames for output

	.PARAMETER zipfilename              
		Filename for the zip

	.PARAMETER nozip                    
		(Default: false) Don't zip files

	.PARAMETER trackcomputercalls       
		(Default: false) Adds a CSV tracking requests to computers

	.PARAMETER zippassword             
		Password protects the zip with the specified password

	.PARAMETER prettyprint              
		(Default: false) Pretty print JSON

	.PARAMETER ldapusername             
		Username for LDAP

	.PARAMETER ldappassword             
		Password for LDAP

	.PARAMETER domaincontroller         
		Override domain controller to pull LDAP from. This option can result in data loss

	.PARAMETER ldapport                 
		(Default: 0) Override port for LDAP

	.PARAMETER secureldap               
		(Default: false) Connect to LDAP SSL instead of regular LDAP

	.PARAMETER disablesigning           
		(Default: false) Disables Kerberos Signing/Sealing

	.PARAMETER skipportcheck            
		(Default: false) Skip checking if 445 is open

	.PARAMETER portchecktimeout         
		(Default: 500) Timeout for port checks in milliseconds

	.PARAMETER excludedcs               
		(Default: false) Exclude domain controllers from session/localgroup enumeration (mostly for ATA/ATP)

	.PARAMETER throttle                 
		Add a delay after computer requests in milliseconds
	
	.PARAMETER jitter                   
		Add jitter to throttle (percent)

	.PARAMETER threads                  
		(Default: 50) Number of threads to run enumeration with

	.PARAMETER skipregistryloggedon     
		Skip registry session enumeration

	.PARAMETER overrideusername         
		Override the username to filter for NetSessionEnum

	.PARAMETER realdnsname              
		Override DNS suffix for API calls

	.PARAMETER collectallproperties     
		Collect all LDAP properties from objects

	.PARAMETER Loop                 
		Loop computer collection

	.PARAMETER loopduration             
		Loop duration (Defaults to 2 hours)

	.PARAMETER loopinterval             
		Delay between loops

	.PARAMETER statusinterval           
		(Default: 30000) Interval in which to display status in milliseconds

	.PARAMETER v                         
		(Default: 2) Enable verbose output

	.PARAMETER help                     
		Display this help screen.

	.PARAMETER version                  
		Display version information.

    .EXAMPLE

        PS C:\> Invoke-BloodHound

        Executes the default collection options and exports JSONs to the current directory, compresses the data to a zip file,
        and then removes the JSON files from disk

    .EXAMPLE

        PS C:\> Invoke-BloodHound -Loop -LoopInterval 00:01:00 -LoopDuration 00:10:00

        Executes session collection in a loop. Will wait 1 minute after each run to continue collection
        and will continue running for 10 minutes after which the script will exit

    .EXAMPLE

        PS C:\> Invoke-BloodHound -CollectionMethods All

        Runs ACL, ObjectProps, Container, and Default collection methods, compresses the data to a zip file,
        and then removes the JSON files from disk

    .EXAMPLE

        PS C:\> Invoke-BloodHound -CollectionMethods DCOnly -NoSaveCache -RandomFilenames -EncryptZip

        (Opsec!) Run LDAP only collection methods (Groups, Trusts, ObjectProps, ACL, Containers, GPO Admins) without outputting the cache file to disk.
        Randomizes filenames of the JSON files and the zip file and adds a password to the zip file
    #>

    [CmdletBinding(PositionalBinding=$false)]
    param(
        [Alias("c")]
        [String[]]
        $CollectionMethods = [String[]] @('Default'),
        
		[Alias("d")]
        [String]
        $Domain,
		
		[Switch]
		[Alias("s")]
        $SearchForest,

        [Switch]
        $Stealth,
		
		[String]
        $f,
		
		[String]
        $DistinguishedName,
		
		[String]
		$ComputerFile,
		
        [ValidateScript({ Test-Path -Path $_ })]
        [String]
        $OutputDirectory = $(Get-Location),

        [ValidateNotNullOrEmpty()]
        [String]
        $OutputPrefix,
		
		[String]
		$CacheName,
		
		[Switch]
		$MemCache,
		
		[Switch]
		$RebuildCache,
		
		[Switch]
		$RandomFileNames,
		
		[String]
		$ZipFileName,
		
		[Switch]
		$NoZip,
		
		[Switch]
		$TrackComputerCalls,
		
		[String]
		$ZipPassword,
		
		[Switch]
		$PrettyPrint,
		
		[String]
		$LDAPUserName,
		
		[String]
		$LDAPPassword,
		
		[String]
		$DomainController,
		
        [ValidateRange(0,65535)]
        [Int]
        $LdapPort,
		
		[Switch]
		$SecureLDAP,
		
		[Switch]
		$DisableSigning,
		
		[Switch]
		$SkipPortCheck,
		
        [ValidateRange(50,5000)]
        [Int]
        $PortCheckTimeout = 2000,
		
		[Switch]
		$ExcludeDCs,
		
		[String]
		$Throttle,
		
        [ValidateRange(0,100)]
        [Int]
        $Jitter,
		
		[Int]
		$Threads,
		
		[Switch]
		$SkipRegistryLoggedOn,
		
		[String]
		$OverrideUserName,
		
		[String]
		$RealDNSName,
		
		[Switch]
		$CollectAllProperties,
		
		[Switch]
		$Loop,
		
		[String]
		$LoopDuration,
		
		[String]
		$LoopInterval,
		
		[ValidateRange(500,60000)]
		[Int]
		$StatusInterval,
		
		[Switch]
		$V,
		
		[Switch]
		[Alias("h")]
		$Help,
		
		[Switch]
		$Version

    )

    $vars = New-Object System.Collections.Generic.List[System.Object]

    if ($CollectionMethods){
        $vars.Add("--CollectionMethods");
        foreach ($cmethod in $CollectionMethods){
            $vars.Add($cmethod);
        }
    }

    if ($Domain){
        $vars.Add("--Domain");
        $vars.Add($Domain);
    }

    if ($SearchForest){
        $vars.Add("--searchforest");
    }

    if ($Stealth){
        $vars.Add("--Stealth");
    }
	
	if ($F){
		$vars.Add("-f");
		$vars.Add($F);
    }
		
	if ($DistinguishedName){
		$vars.Add("--DistinguishedName");
		$vars.Add($DistinguishedName);
    }
	
	if ($ComputerFile){
		$vars.Add("--ComputerFile");
		$vars.Add($ComputerFile);
    }
		
	if ($OutputDirectory){
		$vars.Add("--OutputDirectory");
		$vars.Add($OutputDirectory);
    }
		
    if ($OutputPrefix){
        $vars.Add("--OutputPrefix");
        $vars.Add($OutputPrefix);
    }
		
    if ($CacheName){
        $vars.Add("--CacheName");
        $vars.Add($CacheName);
    }
			
    if ($MemCache){
        $vars.Add("--MemCache");
    }
	
    if ($RebuildCache){
        $vars.Add("--rebuildcache");
    }
	
     if ($RandomFileNames){
        $vars.Add("--RandomFileNames");
    }
	
    if ($ZipFileName){
        $vars.Add("--ZipFileName");
        $vars.Add($ZipFileName);
    }

    if ($NoZip){
        $vars.Add("--NoZip");
    }
	
	if ($TrackComputerCalls){
		$vars.Add("--TrackComputerCalls");
    }
	
	if ($ZipPassword){
		$vars.Add("--ZipPassword");
		$vars.Add($ZipPassword);
    }
		
	if ($PrettyPrint){
		$vars.Add("--PrettyPrint");
    }
		
	if ($LDAPUserName){
		$vars.Add("--LDAPUserName");
		$vars.Add($LDAPUserName);
    }
		
	if ($LDAPPassword){
		$vars.Add("--LDAPPassword");
		$vars.Add($LDAPPassword);
    }
			
	if ($DomainController){
		$vars.Add("--DomainController");
		$vars.Add($DomainController);
    }
			
	if ($LdapPort){
		$vars.Add("--LdapPort");
		$vars.Add($LdapPort);
    }
				
	if ($SecureLDAP){
		$vars.Add("--SecureLDAP");
    }
					
	if ($DisableSigning){
		$vars.Add("--DisableSigning");
    }
						
	if ($SkipPortCheck){
		$vars.Add("--SkipPortCheck");
    }
							
	if ($PortCheckTimeout){
		$vars.Add("--PortCheckTimeout");
		$vars.Add("$PortCheckTimeout");
    }
							
	if ($ExcludeDCs){
		$vars.Add("--ExcludeDCs");
    }
	
    if ($Throttle){
        $vars.Add("--Throttle");
        $vars.Add($Throttle);
    }
	
    if ($Jitter -gt 0){
        $vars.Add("--Jitter");
        $vars.Add($Jitter);
    }
	
	if ($Threads -gt 0){
        $vars.Add("--Threads");
        $vars.Add($Threads);
    }
	
	if ($SkipRegistryLoggedOn){
        $vars.Add("--SkipRegistryLoggedOn");
    }
		
	if ($OverrideUserName){
        $vars.Add("--OverrideUserName");
        $vars.Add($OverrideUserName);
    }
			
	if ($RealDNSName){
        $vars.Add("--RealDNSName");
        $vars.Add($RealDNSName);
    }
				
	if ($CollectAllProperties){
        $vars.Add("--CollectAllProperties");
    }
					
	if ($Loop){
        $vars.Add("--Loop");
    }
	
    if ($LoopDuration){
        $vars.Add("--LoopDuration");
        $vars.Add($LoopDuration);
    }

    if ($LoopInterval){
        $vars.Add("--LoopInterval");
        $vars.Add($LoopInterval);
    }
	
    if ($StatusInterval){
        $vars.Add("--StatusInterval");
        $vars.Add($StatusInterval);
    }
	
    if ($V){
        $vars.Add("-v");
    }

    if ($Help){
        $vars.Add("--Help");
    }

    if ($Version){
        $vars.clear();
        $vars.Add("--Version");
    }

    $passed = [string[]]$vars.ToArray()


    #ENCODEDCONTENTHERE
}

