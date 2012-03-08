
// GHKeyBrowserDlg.h : header file
//

#pragma once


// CGHKeyBrowserDlg dialog
class CGHKeyBrowserDlg : public CDialogEx
{
// Construction
public:
	CGHKeyBrowserDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	enum { IDD = IDD_GHKEYBROWSER_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support



// Implementation
protected:
	HICON m_hIcon;

	bool RunSshKeyGenOnKey(wchar_t* fileFullPath, HANDLE hPipeWrite);
	void CalcHashByHand(wchar_t* fileFullPath, wchar_t* existingBuf);

	// Generated message map functions
	virtual BOOL OnInitDialog();

	afx_msg void OnGetMinMaxInfo(MINMAXINFO* mmi);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
};
