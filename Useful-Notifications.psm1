<#
Useful Notifications PowerShell module (hughowens@gmail.com) 
Copyright (C) 2016 Hugh Owens 
 
This program is free software: you can redistribute it and/or modify 
it under the terms of the GNU General Public License as published by 
the Free Software Foundation, either version 3 of the License, or 
(at your option) any later version. 
 
This program is distributed in the hope that it will be useful, 
but WITHOUT ANY WARRANTY; without even the implied warranty of 
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
GNU General Public License for more details. 
 
You should have received a copy of the GNU General Public License 
along with this program. If not, see <http://www.gnu.org/licenses/>. 
#>

Function Send-PasswordReminder{
	param (
			[string]$configFile = "$(Split-Path -parent $PSCommandPath)\config.xml"
		)
	#Global Settings
	$SubjectPrefix = "Warning"
	$s = Get-NotifyConfig($configFile)
	#Company Specific Settings - Grab from Config File or use  defaults
	$AdminEmail = $(if($S.s.company.AdminEmail){$S.s.company.AdminEmail}else{
		"support@company.com"})
	$FromEmail = $(if($S.s.email.FromEmail){$S.s.email.FromEmail}else{
		"support@company.com"})
	$SMTPServer = $(if($s.s.email.SMTPServer){$s.s.email.SMTPServer}else{
		"smtp.company.com"})
	$SMTPPort = $(if ($s.s.email.Port){$s.s.email.Port}else{
		25})
	$CompanyShortName = $(if($s.s.Company.CompanyShortName){$s.s.Company.CompanyShortName}else{
		"Company"})
	$WebmailLink = $(if($s.s.Company.WebmailLink){$s.s.Company.WebmailLink}else{
		"https://webmail.company.com/owa"})
	$SenderName = $(if($s.s.Company.SenderName){$s.s.Company.SenderName}else{
		"CompanyName IT Support"})
	$SupportPhone = $(if($s.s.Company.SupportPhone){$s.s.Company.SupportPhone}else{
		"00 1234 5678"})
	$EmailContentFile =  $(if($s.s.Company.EmailContent){$s.s.Company.EmailContent}else{
		"PasswordChangeEmail.txt"})

	$EmailContent = $(if($PSScriptRoot){
						Get-Content "$($PSScriptRoot)\$($EmailContentFile)"
					 }else{
						Get-Content $EmailContentFile
					 })
	#Misc Config
	$testmode  = [System.Convert]::ToBoolean($(if($s.s.testmode){$s.s.testmode}else{
		$true}))
	$NotifyEmail = [System.Convert]::ToBoolean($(if($s.s.NotifyEmail){$s.s.NotifyEmail}else{
		$true}))
	$NotifySlack = [System.Convert]::ToBoolean($(if($s.s.NotifySlack){$s.s.NotifySlack}else{
		$true}))
    
	#Defined Warning Levels
	$LevelWarning  = $(if($s.s.WarningLevel.Warning){$s.s.WarningLevel.Warning}else{
		14})
	$LevelUrgent = $(if($s.s.WarningLevel.Urgent){$s.s.WarningLevel.Urgent}else{
		3})
	$LevelCritical = $(if($s.s.WarningLevel.Critical){$s.s.WarningLevel.Critical}else{
		1})
					 
	$DefaultMaxPasswordAge = (Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop).MaxPasswordAge.Days  
	$UsersToReport = @() 
	$users = Get-ADUser -filter {(Enabled -eq $true) -and 
									(PasswordNeverExpires -eq $false) -and
									(PasswordExpired -eq $false)
								} -properties Name,givenName,PasswordNeverExpires,PasswordExpired,PasswordLastSet,EmailAddress
	:NextUser
	foreach ($user in $Users){
		#Calculate Days to expire
		$PasswordPol = (Get-AduserResultantPasswordPolicy $user)  
		$MaxPasswordAge = $DefaultMaxPasswordAge
		if (($PasswordPol) -ne $null){ 
				$MaxPasswordAge = ($PasswordPol).MaxPasswordAge.Days 
		} 
		$ExpiryDate = (get-date $User.PasswordLastSet).AddDays($maxPasswordAge) 
		[int] $DaysToExpire = (New-TimeSpan -Start (get-date) -End $ExpiryDate).Days 
		switch ($DaysToExpire){
			{$_ -gt $LevelWarning}             				{continue NextUser;}
			{$_ -lt 0}              						{continue NextUser;}
			{$LevelUrgent..$LevelWarning -contains $_}    	{$ExpireMessage = "$DaysToExpire days";$SubjectPrefix = "Warning";}
			$LevelUrgent				                    {$ExpireMessage = "2 days"; $SubjectPrefix = "Urgent";}
			{0..$LevelCritical -contains $_} 			    {$ExpireMessage = "1 day"; $SubjectPrefix = "Critical";}
			default     			{write-host "$($user.name) expires in $DaysToExpire days, this is DEFAULT ACTION";continue}
		}
		#Customise email content for this user
		$PersonalisedEmail = [String] $EmailContent -Replace 
										"VAR_GivenName", $User.givenName -replace
										"VAR_ExpireTime",$ExpireMessage -replace
										"VAR_CompanyName",$CompanyShortName -replace
										"VAR_SenderName",$SenderName -replace
										"VAR_SupportPhoneNumber",$SupportPhone -replace
										"VAR_Webmail", $WebmailLink
		
        #Add user object for reporting
        $userObj = New-Object System.Object 
		$userObj | Add-Member -Type NoteProperty -Name "Name" -Value $User.Name 
		$userObj | Add-Member -Type NoteProperty -Name "Email" -Value $User.EmailAddress
		$userObj | Add-Member -Type NoteProperty -Name "Days Left" -Value $DaysToExpire
		$UsersToReport += $userObj
		
		#Create Email Parameters to send
		write-host "Sending email to $($user.Name) for password with $DaysToExpire days left"
		$messageParameters = @{
			Subject = "$SubjectPrefix - Password due to expire in $ExpireMessage."
			Body = $PersonalisedEmail
			From = $FromEmail
			To = "$(if($TestMode){$AdminEmail}else{$User.EmailAddress})"
			#To = "itsupport@satterley.com.au"
			SmtpServer = $SMTPServer
			Port = $SMTPPort
		}
		Send-MailMessage @messageParameters -BodyAsHtml
	}
	
	# Reporting to Administrator
	$report = $UsersToReport | ft | Out-String
	if ($NotifyEmail){
		 $messageParameters = @{
			Subject = "Password Expiry Report."                     
			Body = [string] ("<pre><code>$($report)</code></pre>") 
			From = $FromEmail
			To = $AdminEmail
			SmtpServer = $SMTPServer
			Port = $SMTPPort
		}                        
		Send-MailMessage @messageParameters -BodyAsHtml
	}
	if($NotifySlack){
        Write-Output "Sending notification to slack"
		Send-SlackMessage -message $report -username "Password Expiry" -unicode
	}
	return $UsersToReport
}

function Send-SlackMessage{
	param (
		[string]$configFile = "$(Split-Path -parent $PSCommandPath)\config.xml",
		[String]$channel,
        [String]$IconEmoji,
        [String]$username,
        [String]$message,
        [String]$Webhook,
        [switch]$unicode = $false
	)

    if(!$Webhook){$Webhook = $Settings.s.slack.webhook}
    if(!$IconEmoji){$IconEmoji = $Settings.s.slack.IconEmoji}
    if(!$channel){$channel = $Settings.s.slack.channel}
    if(!$username){$username = $Settings.s.slack.UserName}

    $Settings = Get-NotifyConfig($configFile)
    if($unicode){$message = "``````$message``````"}

    $payload = @{
	    channel = "$($channel)"
	    icon_emoji = "$($IconEmoji)"
	    text = "$message"
	    username = "$($username)"
    }
    $Request = @{
        Body = (ConvertTo-Json -Compress -InputObject $payload) 
        Method = 'Post' 
	    Uri = "$($Settings.s.slack.Webhook)"
    }
    Invoke-WebRequest @Request -UseBasicParsing | out-null
}

Function Get-NotifyConfig($configFile){
    Set-StrictMode -Off
    if ($configFile.length -and (test-path $ConfigFile)){
		write-output "Config File specified in command line"
		$cf = $ConfigFile
	}elseif($PSCommandPath.length -gt 0){
        $LocalPath = (join-path $(Split-Path -parent $PSCommandPath) "config.xml" )
		write-output "looking for local config file"
        $cf = $LocalPath
    }    
    write-host "Using config file: "$cf
    [xml] $settings = Get-Content $cf
    return $settings
}
