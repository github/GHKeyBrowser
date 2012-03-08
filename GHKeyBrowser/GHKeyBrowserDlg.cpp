
// GHKeyBrowserDlg.cpp : implementation file
//

#include "stdafx.h"
#include "GHKeyBrowser.h"
#include "GHKeyBrowserDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


#include <math.h>
#include <stdint.h>
#include <stdlib.h>

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
								'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
								'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
								'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
								'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
								'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
								'w', 'x', 'y', 'z', '0', '1', '2', '3',
								'4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};

char *base64_decode(const char *data,
					size_t input_length,
					size_t *output_length) 
{
	if (input_length % 4 != 0) return NULL;
	
	*output_length = input_length / 4 * 3;
	if (data[input_length - 1] == '=') (*output_length)--;
	if (data[input_length - 2] == '=') (*output_length)--;
	
	char *decoded_data = new char[*output_length];
	if (decoded_data == NULL) return NULL;
	
	for (int i = 0, j = 0; i < input_length;) {
		
		uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		
		uint32_t triple = (sextet_a << 3 * 6)
						+ (sextet_b << 2 * 6)
						+ (sextet_c << 1 * 6)
						+ (sextet_d << 0 * 6);
		
		if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
		if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
		if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
	}
	
	return decoded_data;
}


void build_decoding_table() 
{
	decoding_table = new char[256];
	
	for (int i = 0; i < 0x40; i++)
		decoding_table[encoding_table[i]] = i;
}


void base64_cleanup() {
	free(decoding_table);
}

// CGHKeyBrowserDlg dialog

CGHKeyBrowserDlg::CGHKeyBrowserDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CGHKeyBrowserDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CGHKeyBrowserDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CGHKeyBrowserDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &CGHKeyBrowserDlg::OnBnClickedOk)
	ON_WM_GETMINMAXINFO()
END_MESSAGE_MAP()


// CGHKeyBrowserDlg message handlers

void CGHKeyBrowserDlg::CalcHashByHand(wchar_t* fileFullPath, wchar_t* existingBuf)
{
	char* input_buf = new char[1024*1024];

	DWORD input_size = 0;
	HANDLE hInput = CreateFile(fileFullPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	ReadFile(hInput, input_buf, 1024*1024*sizeof(char), &input_size, NULL);
	CloseHandle(hInput);

	if (input_size <= 0) {
		return;
	}

	char* hash_start;
	int hash_size;
	for(int i=0; i < input_size; i++) {
		if (input_buf[i] == ' ') {
			hash_start = input_buf + i + 1;
			hash_size = input_size - i - 1;
			break;
		}
	}

	for(int i=0; i < hash_size; i++) {
		if (hash_start[i] == ' ') {
			hash_start[i] = 0;
			hash_size = strlen(hash_start);
			hash_start[i] = ' ';
			break;
		}
	}

	size_t decoded_size;
	char* decoded_data = base64_decode(hash_start, hash_size, &decoded_size);

	HCRYPTPROV hProv;
	HCRYPTHASH hMD5;
	CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
	CryptCreateHash(hProv, CALG_MD5, 0, 0, &hMD5);

	BYTE md5Buf[16];
	DWORD cbHash;
	CryptHashData(hMD5, (const BYTE*)decoded_data, decoded_size, 0);
	CryptGetHashParam(hMD5, HP_HASHVAL, md5Buf, &cbHash, 0);
	CryptDestroyHash(hMD5);
	CryptReleaseContext(hProv, 0);

	wchar_t result[MAX_PATH];
	wsprintf(result, L"%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x  %s\n",
		md5Buf[0], md5Buf[1], md5Buf[2], md5Buf[3], md5Buf[4], md5Buf[5], md5Buf[6], md5Buf[7],
		md5Buf[8], md5Buf[9], md5Buf[10], md5Buf[11], md5Buf[12], md5Buf[13], md5Buf[14], md5Buf[15],
		fileFullPath);

	wcscat(existingBuf, result);
}

bool CGHKeyBrowserDlg::RunSshKeyGenOnKey(wchar_t* fileFullPath, HANDLE hPipeWrite)
{
	wchar_t ssh_keygen_path[MAX_PATH];

	ExpandEnvironmentStrings(L"%ProgramFiles%\\Git\\bin\\ssh-keygen.exe", ssh_keygen_path, MAX_PATH);
	//ExpandEnvironmentStrings(L"C:\\Users\\Paul\\AppData\\Local\\GitHub\\PortableGit_1.7.9.0\\bin\\ssh-keygen.exe", ssh_keygen_path, MAX_PATH);
	if (GetFileAttributes(ssh_keygen_path) == 0xFFFFFFFF) {
		return false;
	}

	wcscat(ssh_keygen_path, L" -lf ");
	wcscat(ssh_keygen_path, L"\"");
	wcscat(ssh_keygen_path, fileFullPath);
	wcscat(ssh_keygen_path, L"\"");

	// Create our process
	STARTUPINFO si;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	si.hStdOutput = hPipeWrite;
	si.hStdError = hPipeWrite;
	si.dwFlags |= STARTF_USESTDHANDLES;
	si.wShowWindow = SW_MINIMIZE;

	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));
	
	if (!CreateProcess(NULL, ssh_keygen_path, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
		return false;
	}

	if (WaitForSingleObject(pi.hProcess, 60 * 1000) == WAIT_TIMEOUT) {
		TerminateProcess(pi.hProcess, -1);
		return false;
	}

	return true;
}

BOOL CGHKeyBrowserDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// Set up pipes
	SECURITY_ATTRIBUTES sa;
	sa.nLength = sizeof(sa); sa.bInheritHandle = TRUE; sa.lpSecurityDescriptor = NULL;
	HANDLE hChildStdOutRd, hChildStdOutWr;
	CreatePipe(&hChildStdOutRd, &hChildStdOutWr, &sa, 0);
	SetHandleInformation(hChildStdOutRd, HANDLE_FLAG_INHERIT, 0);

	wchar_t ssh_path[MAX_PATH];
	ExpandEnvironmentStrings(L"%HOMEDRIVE%%HOMEPATH%\\.ssh", ssh_path, MAX_PATH);
	if (GetFileAttributes(ssh_path) == 0xFFFFFFFF) {
		MessageBox(L"You don't appear to have any SSH keys!", L"~/.ssh doesn't exist");
		TerminateProcess(GetCurrentProcess(), -1);
	}

	WIN32_FIND_DATA fd;
	wcscat(ssh_path, L"\\*.pub");
	HANDLE hFd = FindFirstFile(ssh_path, &fd);

	wchar_t* fallback_buf = NULL;

	do {
		ExpandEnvironmentStrings(L"%HOMEDRIVE%%HOMEPATH%\\.ssh", ssh_path, MAX_PATH);
		wcscat(ssh_path, L"\\");
		wcscat(ssh_path, fd.cFileName);

		if (!RunSshKeyGenOnKey(ssh_path, hChildStdOutWr)) {
			if (!fallback_buf) {
				build_decoding_table();
				fallback_buf = new wchar_t[8192];
				fallback_buf[0] = 0;
			}

			CalcHashByHand(ssh_path, fallback_buf);
		}
	} while (FindNextFile(hFd, &fd) != 0);

	FindClose(hFd);

	wchar_t* utf16buf = fallback_buf;

	if (!utf16buf) {
		CloseHandle(hChildStdOutWr);

		char* buf = new char[1024*1024];
		DWORD dwBytesRead;
		ZeroMemory(buf, sizeof(char) * 1024*1024);

		ReadFile(hChildStdOutRd, buf, 1024*1024*sizeof(char), &dwBytesRead, NULL);

		utf16buf = new wchar_t[1024*1024];
		MultiByteToWideChar(CP_UTF8, 0, buf, -1, utf16buf, 1024*1024);
		delete[] buf;
	} 
	
	CString str(utf16buf);
	str.Replace(L"\n", L"\r\n");

	CEdit* pEd = (CEdit*)GetDlgItem(IDC_EDIT1);
	pEd->SetWindowTextW(str);

	return TRUE;  // return TRUE  unless you set the focus to a control
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CGHKeyBrowserDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

void CGHKeyBrowserDlg::OnGetMinMaxInfo(MINMAXINFO* mmi)
{
	RECT r;
	this->GetWindowRect(&r);

	if (r.bottom - r.top < 10) {
		return;
	}

	mmi->ptMaxSize.x = r.right - r.left;
	mmi->ptMaxSize.y = r.bottom - r.top;
	mmi->ptMinTrackSize.x = r.right - r.left;
	mmi->ptMinTrackSize.y = r.bottom - r.top;
	mmi->ptMaxTrackSize.x = r.right - r.left;
	mmi->ptMaxTrackSize.y = r.bottom - r.top;
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CGHKeyBrowserDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CGHKeyBrowserDlg::OnBnClickedOk()
{
	TerminateProcess(GetCurrentProcess(), 0);
}
