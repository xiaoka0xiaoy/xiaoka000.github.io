For test
Don't care about the content


pattern = re.complie('<div.*?author">a.*?img.*?>(.*?)</a>.*?<div.*?'+ 'content">(.*?)<!--(.*?)-->.*?</div>(.*?)<div class="stats.*?class="number">(.*?)</i>',re.s)
    items =re.findall(pattern,content)
  import requests
from bs4 import BeautifulSoup
import os, time
import re
# import http.cookiejar as cookielib
  agent = 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Mobile Safari/537.36'
headers = {
    "Host": "www.zhihu.com",
    "Referer": "https://www.zhihu.com/",
    'User-Agent': agent
}randomtime = str(int(time.time() * 1000))
captchaurl = 'https://www.zhihu.com/captcha.gif?r='+\
             randomtime+"&type=login"
captcharesponse = session.get(url=captchaurl, headers=headers)
with open('checkcode.gif', 'wb') as f:
    f.write(captcharesponse.content)
    f.close()
# os.startfile('checkcode.gif')
captcha = input('')
print(captcha)
  import time
import requests
from xtls.util import BeautifulSoup

def login(username, password, oncaptcha):
    session = requests.session()

    _xsrf = BeautifulSoup(session.get('https://www.zhihu.com/#signin').content).find('input', attrs={'name': '_xsrf'})['value']
    captcha_content = session.get('http://www.zhihu.com/captcha.gif?r=%d' % (time.time() * 1000)).content
    data = {
        '_xsrf': _xsrf,
        'email': username,
        'password': password,
        'remember_me': 'true',
        'captcha': oncaptcha(captcha_content)
    }
    resp = session.post('http://www.zhihu.com/login/email', data).content
    assert '\u767b\u9646\u6210\u529f' in resp
    return session 
Sub abc()
    Shell "cmd.exe /k wevtutil.exe gli Application"
End Sub
wevtutil cl Application
# powershell –exec bypass –Command "& {Import-Module 'C:\Invoke-Phant0m.ps1';Invoke-Phant0m}"
Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36 OPR/26.0.1656.60
Opera/8.0 (Windows NT 5.1; U; en)
Mozilla/5.0 (Windows NT 5.1; U; en; rv:1.8.1) Gecko/20061208 Firefox/2.0.0 Opera 9.50
Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 9.50
Mozilla/5.0 (Windows NT 6.1; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0
Mozilla/5.0 (X11; U; Linux x86_64; zh-CN; rv:1.9.2.10) Gecko/20100922 Ubuntu/10.10 (maverick) Firefox/3.6.10
Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/534.57.2 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2 
Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.71 Safari/537.36
Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11
Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.133 Safari/534.16
Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.101 Safari/537.36
Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko
Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.11 TaoBrowser/2.0 Safari/536.11
Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.71 Safari/537.1 LBBROWSER
Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; LBBROWSER) 
Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; QQDownload 732; .NET4.0C; .NET4.0E; LBBROWSER)" 
Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; QQBrowser/7.0.3698.400)
Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; QQDownload 732; .NET4.0C; .NET4.0E) 
Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.84 Safari/535.11 SE 2.X MetaSr 1.0
Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Maxthon/4.4.3.4000 Chrome/30.0.1599.101 Safari/537.36
Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.122 UBrowser/4.0.3214.0 Safari/537.36
#include <windows.h>
#include <Winternl.h>
#pragma optimize( "", off ) 
void shell_code();
HANDLE GetKernel32Handle();
BOOL __ISUPPER__(__in CHAR c);
CHAR __TOLOWER__(__in CHAR c);
UINT __STRLEN__(__in LPSTR lpStr1);
UINT __STRLENW__(__in LPWSTR lpStr1);
LPWSTR __STRSTRIW__(__in LPWSTR lpStr1, __in LPWSTR lpStr2);
INT __STRCMPI__(__in LPSTR lpStr1, __in LPSTR lpStr2);
INT __STRNCMPIW__(__in LPWSTR lpStr1, __in LPWSTR lpStr2, __in DWORD dwLen);
LPVOID __MEMCPY__(__in LPVOID lpDst, __in LPVOID lpSrc, __in DWORD dwCount);

typedef FARPROC(WINAPI* GetProcAddressAPI)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI* LoadLibraryWAPI)(LPCWSTR);
typedef ULONG (WINAPI *MESSAGEBOXAPI)(HWND, LPWSTR, LPWSTR, ULONG);


void shell_code() {

	LoadLibraryWAPI	loadlibrarywapi = 0;
	GetProcAddressAPI getprocaddressapi=0;
	MESSAGEBOXAPI messageboxapi=0;

	wchar_t struser32[] = { L'u', L's', L'e', L'r', L'3',L'2', L'.', L'd', L'l', L'l', 0 };
	char MeassageboxA_api[] = { 'M', 'e', 's', 's', 'a', 'g', 'e', 'B', 'o', 'x', 'A', 0 };

	HANDLE hKernel32 = GetKernel32Handle();
	if (hKernel32 == INVALID_HANDLE_VALUE) {
		return;
	}
	LPBYTE lpBaseAddr = (LPBYTE)hKernel32;
	PIMAGE_DOS_HEADER lpDosHdr = (PIMAGE_DOS_HEADER)lpBaseAddr;
	PIMAGE_NT_HEADERS pNtHdrs = (PIMAGE_NT_HEADERS)(lpBaseAddr + lpDosHdr->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(lpBaseAddr + pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	LPDWORD pNameArray = (LPDWORD)(lpBaseAddr + pExportDir->AddressOfNames);
	LPDWORD pAddrArray = (LPDWORD)(lpBaseAddr + pExportDir->AddressOfFunctions);
	LPWORD pOrdArray = (LPWORD)(lpBaseAddr + pExportDir->AddressOfNameOrdinals);
	CHAR strLoadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'W', 0x0 };
	CHAR strGetProcAddress[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0x0 };

	for (UINT i = 0; i < pExportDir->NumberOfNames; i++) {
		LPSTR pFuncName = (LPSTR)(lpBaseAddr + pNameArray[i]);
		if (!__STRCMPI__(pFuncName, strGetProcAddress)) {
			getprocaddressapi=(GetProcAddressAPI)(lpBaseAddr + pAddrArray[pOrdArray[i]]);
		}
		else if (!__STRCMPI__(pFuncName, strLoadLibraryA)) {
			loadlibrarywapi=(LoadLibraryWAPI) (lpBaseAddr + pAddrArray[pOrdArray[i]]);
		}
		if (getprocaddressapi != nullptr && loadlibrarywapi != nullptr) {				
			messageboxapi=(MESSAGEBOXAPI)getprocaddressapi(loadlibrarywapi(struser32), MeassageboxA_api);
			messageboxapi(NULL, NULL, NULL, 0);
			return;
		}
	}
}

inline BOOL __ISUPPER__(__in CHAR c) {
	return ('A' <= c) && (c <= 'Z');
};
inline CHAR __TOLOWER__(__in CHAR c) {
	return __ISUPPER__(c) ? c - 'A' + 'a' : c;
};

UINT __STRLEN__(__in LPSTR lpStr1)
{
	UINT i = 0;
	while (lpStr1[i] != 0x0)
		i++;
	return i;
}

UINT __STRLENW__(__in LPWSTR lpStr1)
{
	UINT i = 0;
	while (lpStr1[i] != L'\0')
		i++;
	return i;
}

LPWSTR __STRSTRIW__(__in LPWSTR lpStr1, __in LPWSTR lpStr2)
{
	CHAR c = __TOLOWER__(((PCHAR)(lpStr2++))[0]);
	if (!c)
		return lpStr1;
	UINT dwLen = __STRLENW__(lpStr2);
	do
	{
		CHAR sc;
		do
		{
			sc = __TOLOWER__(((PCHAR)(lpStr1)++)[0]);
			if (!sc)
				return NULL;
		} while (sc != c);
	} while (__STRNCMPIW__(lpStr1, lpStr2, dwLen) != 0);
	return (lpStr1 - 1); // FIXME -2 ?
}

INT __STRCMPI__(
	__in LPSTR lpStr1,
	__in LPSTR lpStr2)
{
	int  v;
	CHAR c1, c2;
	do
	{
		c1 = *lpStr1++;
		c2 = *lpStr2++;
		// The casts are necessary when pStr1 is shorter & char is signed 
		v = (UINT)__TOLOWER__(c1) - (UINT)__TOLOWER__(c2);
	} while ((v == 0) && (c1 != '\0') && (c2 != '\0'));
	return v;
}

INT __STRNCMPIW__(
	__in LPWSTR lpStr1,
	__in LPWSTR lpStr2,
	__in DWORD dwLen)
{
	int  v;
	CHAR c1, c2;
	do {
		dwLen--;
		c1 = ((PCHAR)lpStr1++)[0];
		c2 = ((PCHAR)lpStr2++)[0];
		/* The casts are necessary when pStr1 is shorter & char is signed */
		v = (UINT)__TOLOWER__(c1) - (UINT)__TOLOWER__(c2);
	} while ((v == 0) && (c1 != 0x0) && (c2 != 0x0) && dwLen > 0);
	return v;
}

LPSTR __STRCAT__(
	__in LPSTR	strDest,
	__in LPSTR strSource)
{
	LPSTR d = strDest;
	LPSTR s = strSource;
	while (*d) d++;
	do { *d++ = *s++; } while (*s);
	*d = 0x0;
	return strDest;
}

LPVOID __MEMCPY__(
	__in LPVOID lpDst,
	__in LPVOID lpSrc,
	__in DWORD dwCount)
{
	LPBYTE s = (LPBYTE)lpSrc;
	LPBYTE d = (LPBYTE)lpDst;
	while (dwCount--)
		*d++ = *s++;
	return lpDst;
}

HANDLE GetKernel32Handle() {
	HANDLE hKernel32 = INVALID_HANDLE_VALUE;
#ifdef _WIN64
	PPEB lpPeb = (PPEB)__readgsqword(0x60);
#else
	PPEB lpPeb = (PPEB)__readfsdword(0x30);
#endif
	PLIST_ENTRY pListHead = &lpPeb->Ldr->InMemoryOrderModuleList;
	PLIST_ENTRY pListEntry = pListHead->Flink;
	WCHAR strDllName[MAX_PATH];
	WCHAR strKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', L'\0' };

	while (pListEntry != pListHead) {
		PLDR_DATA_TABLE_ENTRY pModEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (pModEntry->FullDllName.Length) {
			DWORD dwLen = pModEntry->FullDllName.Length;
			__MEMCPY__(strDllName, pModEntry->FullDllName.Buffer, dwLen);
			strDllName[dwLen / sizeof(WCHAR)] = L'\0';
			if (__STRSTRIW__(strDllName, strKernel32)) {
				hKernel32 = pModEntry->DllBase;
				break;
			}
		}
		pListEntry = pListEntry->Flink;
	}
	return hKernel32;
}

int main()
{
	printf("1");
	shell_code();
	printf("2");
	return 0;
  
read -p "请输入要查询的PID: " P
n=`ps -aux| awk '$2~/^'$P'$/{print $11}'|wc -l`
if [ $n -eq 0 ];then
 echo "该PID不存在！！"
 exit
fi
echo "--------------------------------"
echo "进程PID: $P"
echo "进程命令：`ps -aux| awk '$2~/^'$P'$/{print $11}'`"
echo "进程所属用户: `ps -aux| awk '$2~/^'$P'$/{print $1}'`"
echo "CPU占用率：`ps -aux| awk '$2~/^'$P'$/{print $3}'`%"
echo "内存占用率：`ps -aux| awk '$2~/^'$P'$/{print $4}'`%"
echo "进程开始运行的时刻：`ps -aux| awk '$2~/^'$P'$/{print $9}'`"
echo "进程运行的时间：`ps -aux| awk '$2~/^'$P'$/{print $10}'`"
echo "进程状态：`ps -aux| awk '$2~/^'$P'$/{print $8}'`"
echo "进程虚拟内存：`ps -aux| awk '$2~/^'$P'$/{print $5}'`"
echo "进程共享内存：`ps -aux| awk '$2~/^'$P'$/{print $6}'`"
#!/bin/bash

#Shell Env

SHELL_NAME="shell_template.sh"

SHELL_DIR="/opt/shell"

SHELL_LOG="${SHELL_DIR}/${SHELL_NAME}.log"

#Write Log

shell_log() {

LOG_INFO=$1

echo "$(date "+%Y-%m-%d") $(date "+%H-%M-%S") : ${SHELL_NAME} : ${LOG_INFO}" >> ${SHELL_LOG}

}

shell_log "shell beginning ,write log test"

shell_log "shell success ,write log test"
