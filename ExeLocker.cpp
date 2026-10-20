// ExeLocker.cpp
// 可执行文件黑名单锁：托盘常驻 + 开机自启 + 黑名单进程拦截
//

#include "framework.h"
#include "Resource.h"
#include <shellapi.h>
#include <shlobj.h>
#include <commdlg.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <vector>
#include <string>
#include <algorithm>
#include <cctype>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

// ===================== 可配置项 =====================
static const wchar_t* APP_NAME      = L"ExeLocker";              // 注册表 Run 键名
static const wchar_t* TRAY_TIP      = L"可执行文件锁（运行中）";
static const wchar_t* TRAY_TIP_OFF  = L"可执行文件锁（已暂停）";
static const wchar_t* DEFAULT_PASSWORD = L"123456";              // 首次运行的默认密码
static const UINT     WM_TRAYICON   = WM_APP + 1;
static const UINT_PTR TIMER_SCAN    = 1;
static const UINT     SCAN_INTERVAL = 1000;                      // 毫秒，进程轮询间隔
// ====================================================

HINSTANCE hInst;
HWND      g_hWnd = nullptr;
NOTIFYICONDATAW g_nid = {};
HWINEVENTHOOK g_hook = nullptr;
bool      g_lockEnabled = true;          // 是否启用拦截
std::vector<std::wstring> g_blacklist;   // 黑名单（小写进程路径）
std::wstring g_password = DEFAULT_PASSWORD;  // 当前密码

// ---------- 工具函数 ----------
static std::wstring ToLower(std::wstring s)
{
	std::transform(s.begin(), s.end(), s.begin(),
		[](wchar_t c) { return (wchar_t)towlower(c); });
	return s;
}

// 判断某个进程名（小写）是否已在黑名单中
static bool IsBlacklisted(const std::wstring& nameLower)
{
	for (auto& s : g_blacklist)
		if (s == nameLower) return true;
	return false;
}

// 黑名单文件路径：%ProgramData%\ExeLocker\blacklist.txt
static std::wstring GetBlacklistPath()
{
	wchar_t buf[MAX_PATH] = {};
	if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, buf)))
	{
		std::wstring dir = std::wstring(buf) + L"\\ExeLocker";
		CreateDirectoryW(dir.c_str(), nullptr);
		return dir + L"\\blacklist.txt";
	}
	return L"blacklist.txt";
}

static void LoadBlacklist()
{
	g_blacklist.clear();
	FILE* f = nullptr;
	if (_wfopen_s(&f, GetBlacklistPath().c_str(), L"r, ccs=UTF-8") == 0 && f)
	{
		wchar_t line[512];
		while (fgetws(line, 512, f))
		{
			std::wstring s = line;
			while (!s.empty() && (s.back() == L'\r' || s.back() == L'\n' || iswspace(s.back())))
				s.pop_back();
			if (!s.empty())
				g_blacklist.push_back(ToLower(s));
		}
		fclose(f);
	}
}

static void SaveBlacklist()
{
	FILE* f = nullptr;
	if (_wfopen_s(&f, GetBlacklistPath().c_str(), L"w, ccs=UTF-8") == 0 && f)
	{
		for (auto& s : g_blacklist)
			fputws((s + L"\n").c_str(), f);
		fclose(f);
	}
}

// ---------- 密码存取（DPAPI 加密，存 config.bin） ----------
static std::wstring GetConfigPath()
{
	wchar_t buf[MAX_PATH] = {};
	if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, buf)))
	{
		std::wstring dir = std::wstring(buf) + L"\\ExeLocker";
		CreateDirectoryW(dir.c_str(), nullptr);
		return dir + L"\\config.bin";
	}
	return L"config.bin";
}

// 用 DPAPI 加密密码并写入文件
static bool SavePassword(const std::wstring& pwd)
{
	DATA_BLOB in{}, out{};
	in.pbData = (BYTE*)pwd.c_str();
	in.cbData = (DWORD)((pwd.size() + 1) * sizeof(wchar_t));
	if (!CryptProtectData(&in, L"ExeLockerPwd", nullptr, nullptr, nullptr, 0, &out))
		return false;
	FILE* f = nullptr;
	bool ok = false;
	if (_wfopen_s(&f, GetConfigPath().c_str(), L"wb") == 0 && f)
	{
		fwrite(&out.cbData, sizeof(out.cbData), 1, f);
		fwrite(out.pbData, 1, out.cbData, f);
		fclose(f);
		ok = true;
	}
	LocalFree(out.pbData);
	return ok;
}

// 读取并解密密码；文件不存在或解密失败时保持默认密码
static void LoadPassword()
{
	FILE* f = nullptr;
	if (_wfopen_s(&f, GetConfigPath().c_str(), L"rb") != 0 || !f)
		return;
	DWORD cb = 0;
	if (fread(&cb, sizeof(cb), 1, f) != 1 || cb == 0 || cb > 4096)
	{
		fclose(f);
		return;
	}
	std::vector<BYTE> buf(cb);
	if (fread(buf.data(), 1, cb, f) != cb)
	{
		fclose(f);
		return;
	}
	fclose(f);

	DATA_BLOB in{ cb, buf.data() }, out{};
	if (CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out))
	{
		g_password = (const wchar_t*)out.pbData;
		LocalFree(out.pbData);
	}
}

static bool IsBlacklistedPath(const std::wstring& fullPathLower)
{
	for (auto& s : g_blacklist)
		if (s == fullPathLower) return true;
	return false;
}

// ---------- 进程拦截 ----------
static void KillProcessById(DWORD pid)
{
	if (pid == GetCurrentProcessId()) return;
	HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
	if (h)
	{
		TerminateProcess(h, 1);
		CloseHandle(h);
	}
}

// 通过 PID 取进程完整路径，命中黑名单则终止
static void CheckAndKillByPid(DWORD pid)
{
	if (!g_lockEnabled || !pid || pid == GetCurrentProcessId()) return;
	HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (!h) return;
	wchar_t path[MAX_PATH] = {};
	DWORD size = MAX_PATH;
	if (QueryFullProcessImageNameW(h, 0, path, &size))
	{
		if (IsBlacklistedPath(ToLower(path)))
			KillProcessById(pid);
	}
	CloseHandle(h);
}

// 定时器：全量扫描进程快照，堵住无窗口/钩子漏掉的进程
static void ScanAllProcesses()
{
	if (!g_lockEnabled) return;
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE) return;
	PROCESSENTRY32W pe{ sizeof(pe) };
	if (Process32FirstW(snap, &pe))
	{
		do {
			CheckAndKillByPid(pe.th32ProcessID);
		} while (Process32NextW(snap, &pe));
	}
	CloseHandle(snap);
}

// WinEvent 回调：新窗口创建时立即检查其所属进程
static void CALLBACK WinEventProc(HWINEVENTHOOK, DWORD event, HWND hwnd,
	LONG idObject, LONG, DWORD, DWORD)
{
	if (event != EVENT_OBJECT_CREATE || idObject != OBJID_WINDOW || !hwnd) return;
	DWORD pid = 0;
	GetWindowThreadProcessId(hwnd, &pid);
	if (pid) CheckAndKillByPid(pid);
}

// ---------- 注册表开机自启（所有用户：HKLM） ----------
static const wchar_t* RUN_KEY = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

static std::wstring GetSelfPath()
{
	wchar_t buf[MAX_PATH] = {};
	GetModuleFileNameW(nullptr, buf, MAX_PATH);
	return std::wstring(L"\"") + buf + L"\"";
}

static bool IsAutoStartEnabled()
{
	HKEY hKey = nullptr;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, RUN_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
		return false;
	wchar_t val[MAX_PATH * 2] = {};
	DWORD size = sizeof(val);
	LONG r = RegQueryValueExW(hKey, APP_NAME, nullptr, nullptr, (LPBYTE)val, &size);
	RegCloseKey(hKey);
	return r == ERROR_SUCCESS;
}

static void SetAutoStart(bool enable)
{
	HKEY hKey = nullptr;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, RUN_KEY, 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
	{
		MessageBoxW(nullptr, L"需要以管理员身份运行才能设置所有用户的开机自启。", L"权限不足", MB_ICONWARNING);
		return;
	}
	if (enable)
	{
		std::wstring p = GetSelfPath();
		RegSetValueExW(hKey, APP_NAME, 0, REG_SZ,
			(const BYTE*)p.c_str(), (DWORD)((p.size() + 1) * sizeof(wchar_t)));
	}
	else
	{
		RegDeleteValueW(hKey, APP_NAME);
	}
	RegCloseKey(hKey);
}

// ---------- 托盘 ----------
static void TrayAdd(HWND hWnd)
{
	g_nid.cbSize = sizeof(g_nid);
	g_nid.hWnd = hWnd;
	g_nid.uID = 1;
	g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
	g_nid.uCallbackMessage = WM_TRAYICON;
	g_nid.hIcon = LoadIcon(hInst, MAKEINTRESOURCE(IDI_TEST));
	wcscpy_s(g_nid.szTip, TRAY_TIP);
	Shell_NotifyIconW(NIM_ADD, &g_nid);
}

static void TrayRemove()
{
	Shell_NotifyIconW(NIM_DELETE, &g_nid);
}

static void TrayUpdateTip()
{
	wcscpy_s(g_nid.szTip, g_lockEnabled ? TRAY_TIP : TRAY_TIP_OFF);
	Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}

// ---------- 密码验证 ----------
struct PwdDlgState { bool ok = false; };

static INT_PTR CALLBACK PwdDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static PwdDlgState* st;
	switch (msg)
	{
	case WM_INITDIALOG:
		st = (PwdDlgState*)lParam;
		SetFocus(GetDlgItem(hDlg, IDC_EDIT_PASSWORD));
		return FALSE;
	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK)
		{
			wchar_t buf[128] = {};
			GetDlgItemTextW(hDlg, IDC_EDIT_PASSWORD, buf, 128);
			if (wcscmp(buf, g_password.c_str()) == 0)
			{
				st->ok = true;
				EndDialog(hDlg, IDOK);
			}
			else
			{
				MessageBoxW(hDlg, L"密码错误！", L"提示", MB_ICONERROR);
				SetDlgItemTextW(hDlg, IDC_EDIT_PASSWORD, L"");
			}
			return TRUE;
		}
		if (LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, IDCANCEL);
			return TRUE;
		}
		break;
	}
	return FALSE;
}

static bool VerifyPassword(HWND hWnd)
{
	PwdDlgState st;
	DialogBoxParamW(hInst, MAKEINTRESOURCE(IDD_PASSWORD), hWnd, PwdDlgProc, (LPARAM)&st);
	return st.ok;
}

// ---------- 修改密码对话框 ----------
static INT_PTR CALLBACK ChangePwdDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM)
{
	switch (msg)
	{
	case WM_INITDIALOG:
		SetFocus(GetDlgItem(hDlg, IDC_EDIT_OLDPWD));
		return FALSE;
	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK)
		{
			wchar_t oldP[128] = {}, newP[128] = {}, newP2[128] = {};
			GetDlgItemTextW(hDlg, IDC_EDIT_OLDPWD, oldP, 128);
			GetDlgItemTextW(hDlg, IDC_EDIT_NEWPWD, newP, 128);
			GetDlgItemTextW(hDlg, IDC_EDIT_NEWPWD2, newP2, 128);

			if (wcscmp(oldP, g_password.c_str()) != 0)
			{
				MessageBoxW(hDlg, L"当前密码不正确！", L"提示", MB_ICONERROR);
				return TRUE;
			}
			if (newP[0] == L'\0')
			{
				MessageBoxW(hDlg, L"新密码不能为空！", L"提示", MB_ICONWARNING);
				return TRUE;
			}
			if (wcscmp(newP, newP2) != 0)
			{
				MessageBoxW(hDlg, L"两次输入的新密码不一致！", L"提示", MB_ICONWARNING);
				return TRUE;
			}
			if (SavePassword(newP))
			{
				g_password = newP;
				MessageBoxW(hDlg, L"密码修改成功！", L"提示", MB_ICONINFORMATION);
				EndDialog(hDlg, IDOK);
			}
			else
			{
				MessageBoxW(hDlg, L"密码保存失败（可能需要管理员权限）。", L"错误", MB_ICONERROR);
			}
			return TRUE;
		}
		if (LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, IDCANCEL);
			return TRUE;
		}
		break;
	}
	return FALSE;
}

// ---------- 黑名单设置对话框 ----------
static void RefreshList(HWND hDlg)
{
	HWND lb = GetDlgItem(hDlg, IDC_LIST_BLACKLIST);
	SendMessageW(lb, LB_RESETCONTENT, 0, 0);
	for (auto& s : g_blacklist)
		SendMessageW(lb, LB_ADDSTRING, 0, (LPARAM)s.c_str());
}

static INT_PTR CALLBACK SettingsDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM)
{
	switch (msg)
	{
	case WM_INITDIALOG:
		RefreshList(hDlg);
		SetDlgItemTextW(hDlg, IDC_BTN_AUTOSTART,
			IsAutoStartEnabled() ? L"开机自启: 开" : L"开机自启: 关");
		return TRUE;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_BTN_ADD:
		{
			wchar_t buf[MAX_PATH] = {};
			GetDlgItemTextW(hDlg, IDC_EDIT_NEWITEM, buf, MAX_PATH);
			std::wstring s = buf;
			while (!s.empty() && iswspace(s.back())) s.pop_back();
			if (s.empty()) break;
			s = ToLower(s);
			if (!IsBlacklistedPath(s))
			{
				g_blacklist.push_back(s);
				SaveBlacklist();
				RefreshList(hDlg);
			}
			SetDlgItemTextW(hDlg, IDC_EDIT_NEWITEM, L"");
			return TRUE;
		}
		case IDC_BTN_BROWSE:
		{
			wchar_t file[MAX_PATH] = {};
			OPENFILENAMEW ofn{ sizeof(ofn) };
			ofn.hwndOwner = hDlg;
			ofn.lpstrFile = file;
			ofn.nMaxFile = MAX_PATH;
			ofn.lpstrFilter = L"应用程序 (*.exe)\0*.exe\0所有文件 (*.*)\0*.*\0";
			ofn.lpstrTitle = L"选择要禁止的应用程序";
			ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
			if (GetOpenFileNameW(&ofn))
				SetDlgItemTextW(hDlg, IDC_EDIT_NEWITEM, file);
			return TRUE;
		}
		case IDC_BTN_REMOVE:
		{
			HWND lb = GetDlgItem(hDlg, IDC_LIST_BLACKLIST);
			LRESULT sel = SendMessageW(lb, LB_GETCURSEL, 0, 0);
			if (sel != LB_ERR && sel < (LRESULT)g_blacklist.size())
			{
				g_blacklist.erase(g_blacklist.begin() + sel);
				SaveBlacklist();
				RefreshList(hDlg);
			}
			return TRUE;
		}
		case IDC_BTN_AUTOSTART:
		{
			bool now = !IsAutoStartEnabled();
			SetAutoStart(now);
			SetDlgItemTextW(hDlg, IDC_BTN_AUTOSTART,
				IsAutoStartEnabled() ? L"开机自启: 开" : L"开机自启: 关");
			return TRUE;
		}
		case IDC_BTN_CHANGEPWD:
			DialogBoxW(hInst, MAKEINTRESOURCE(IDD_CHANGEPWD), hDlg, ChangePwdDlgProc);
			return TRUE;
		case IDOK:
		case IDCANCEL:
			EndDialog(hDlg, LOWORD(wParam));
			return TRUE;
		}
		break;
	}
	return FALSE;
}

// ---------- 托盘菜单 ----------
static void ShowTrayMenu(HWND hWnd)
{
	HMENU menu = CreatePopupMenu();
	AppendMenuW(menu, MF_STRING, ID_TRAY_SETTINGS, L"设置黑名单...");
	AppendMenuW(menu, MF_STRING, ID_TRAY_TOGGLE,
		g_lockEnabled ? L"暂停锁定" : L"恢复锁定");
	AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
	AppendMenuW(menu, MF_STRING, ID_TRAY_EXIT, L"退出");

	POINT pt{};
	GetCursorPos(&pt);
	SetForegroundWindow(hWnd);
	TrackPopupMenu(menu, TPM_BOTTOMALIGN | TPM_LEFTALIGN, pt.x, pt.y, 0, hWnd, nullptr);
	DestroyMenu(menu);
}

// ---------- 主窗口过程 ----------
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_CREATE:
		TrayAdd(hWnd);
		SetTimer(hWnd, TIMER_SCAN, SCAN_INTERVAL, nullptr);
		break;

	case WM_TIMER:
		if (wParam == TIMER_SCAN) ScanAllProcesses();
		break;

	case WM_TRAYICON:
		if (LOWORD(lParam) == WM_RBUTTONUP || LOWORD(lParam) == WM_CONTEXTMENU)
			ShowTrayMenu(hWnd);
		else if (LOWORD(lParam) == WM_LBUTTONDBLCLK)
			SendMessageW(hWnd, WM_COMMAND, ID_TRAY_SETTINGS, 0);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case ID_TRAY_SETTINGS:
			if (VerifyPassword(hWnd))
				DialogBoxW(hInst, MAKEINTRESOURCE(IDD_SETTINGS), hWnd, SettingsDlgProc);
			break;
		case ID_TRAY_TOGGLE:
			if (VerifyPassword(hWnd))
			{
				g_lockEnabled = !g_lockEnabled;
				TrayUpdateTip();
			}
			break;
		case ID_TRAY_EXIT:
			if (VerifyPassword(hWnd))
				DestroyWindow(hWnd);
			break;
		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
		}
		break;

	case WM_DESTROY:
		KillTimer(hWnd, TIMER_SCAN);
		TrayRemove();
		PostQuitMessage(0);
		break;

	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}

// ---------- 入口 ----------
int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE, _In_ LPWSTR, _In_ int)
{
	hInst = hInstance;

	// 单实例
	HANDLE mutex = CreateMutexW(nullptr, TRUE, L"Global\\ExeLocker_SingleInstance");
	if (!mutex)
	{
		MessageBoxW(nullptr, L"无法创建互斥体，程序将退出。", L"错误", MB_ICONERROR);
		return 1;
	}
	if (GetLastError() == ERROR_ALREADY_EXISTS)
	{
		MessageBoxW(nullptr, L"程序已在运行。", L"提示", MB_ICONINFORMATION);
		CloseHandle(mutex);
		return 0;
	}

	LoadPassword();
	LoadBlacklist();

	// 注册一个仅用于接收消息的隐藏窗口
	WNDCLASSEXW wcex{ sizeof(wcex) };
	wcex.lpfnWndProc = WndProc;
	wcex.hInstance = hInstance;
	wcex.lpszClassName = L"ExeLockerHiddenWnd";
	RegisterClassExW(&wcex);

	g_hWnd = CreateWindowW(L"ExeLockerHiddenWnd", L"", 0,
		0, 0, 0, 0, HWND_MESSAGE, nullptr, hInstance, nullptr);
	if (!g_hWnd)
	{
		CloseHandle(mutex);
		return 1;
	}

	// 安装全局 WinEvent 钩子：监听新窗口创建
	g_hook = SetWinEventHook(EVENT_OBJECT_CREATE, EVENT_OBJECT_CREATE,
		nullptr, WinEventProc, 0, 0, WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);

	MSG msg{};
	while (GetMessage(&msg, nullptr, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	if (g_hook) UnhookWinEvent(g_hook);
	if (mutex)
	{
		ReleaseMutex(mutex);
		CloseHandle(mutex);
	}
	return (int)msg.wParam;
}
