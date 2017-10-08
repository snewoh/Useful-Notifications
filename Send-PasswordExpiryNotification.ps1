#Global Settings
$TestMode =$true
$SendReport = $true
$SubjectPrefex = "Warning"

#Company Specific Settings
$AdminEmail = "itsupport@Company.com"
$SMTPServer = "smtp.Company.com"
$EmailContent = $(if($PSScriptRoot){
                    Get-Content "$($PSScriptRoot)\PasswordChangeEmail.txt"
                 }else{
                    "PasswordChangeEmail.txt"
                 })
$CompanyShortName = "Company"
$WebmailLink = "https://webmail.Company.com/owa"
$SenderName = "Company IT Support"
$SenderEmail = "itsupport@Company.com"
$DefaultMaxPasswordAge = (Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop).MaxPasswordAge.Days  
$UsersToReport = @() 
$users = Get-ADUser -filter {(Enabled -eq $true) -and 
                                (PasswordNeverExpires -eq $false) -and
                                (PasswordExpired -eq $false)
                            } -properties Name,givenName,PasswordNeverExpires,PasswordExpired,PasswordLastSet,EmailAddress

foreach ($user in $Users){
    #Calculate Days to expire
    $PasswordPol = (Get-AduserResultantPasswordPolicy $user)  
    $MaxPasswordAge = $DefaultMaxPasswordAge
    if (($PasswordPol) -ne $null){ 
            $MaxPasswordAge = ($PasswordPol).MaxPasswordAge.Days 
    } 
    $ExpiryDate = (get-date $User.PasswordLastSet).AddDays($maxPasswordAge) 
    $DaysToExpire = (New-TimeSpan -Start (get-date) -End $ExpiryDate).Days 

    switch ($DaysToExpire){
        3..14 {$ExpireMessage = "$DaysToExpire days";}
        2     {$ExpireMessage = "2 days"; $SubjectPrefex = "Urgent";}
        0..1  {$ExpireMessage = "1 day"; $SubjectPrefex = "Critical";}

    }
    #Customise email for this user
    $PersonalisedEmail = [String] $EmailContent -Replace 
                                    "VAR_GivenName", $User.givenName -replace
                                    "VAR_ExpireTime",$ExpireMessage -replace
                                    "VAR_CompanyName",$CompanyShortName -replace
                                    "VAR_SenderName",$SenderEmail
    #Add user to report object
    if ($sendReport -and $DaysToExpire -lt 15 -and $DaysToExpire -ge 0){
        $userObj = New-Object System.Object 
        $userObj | Add-Member -Type NoteProperty -Name "Name" -Value $User.Name 
        $userObj | Add-Member -Type NoteProperty -Name "Email" -Value $User.EmailAddress
        $userObj | Add-Member -Type NoteProperty -Name "Days Left" -Value $DaysToExpire
        $UsersToReport += $userObj
    }
    #Send Email
    $messageParameters = @{
        Subject = "$SubjectPrefx - Password due to expire in $ExpireMessage."
        Body = $PersonalisedEmail
        From = $SenderEmail
        To = "$(if($TestMode){$SenderEmail}else{$User.EmailAddress})"
        SmtpServer = $SMTPServer
        Port = 25
    }                        
    Send-MailMessage @messageParameters -BodyAsHtml 
}
if ($sendReport){
     $messageParameters = @{
        Subject = "Password Expiry Report."                     
        Body = [string] $($UsersToReport | ft)
        From = $SenderEmail
        To = "$(if($TestMode){$SenderEmail}else{$User.EmailAddress})"
        SmtpServer = $SMTPServer
        Port = 25
    }                        
    Send-MailMessage @messageParameters
}
