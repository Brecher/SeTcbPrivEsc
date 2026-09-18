# TcbPrivEsc

PoC для PrivEsc в Windows через `SeTcbPrivilege` и S4U-логин с добавлением SID `S-1-5-18` в группы токена.

**Только для образовательных целей.** Проект является ресёрчем по теме токенов доступа Windows и механизмов аутентификации LSA.

---

## О проекте

Это адаптация оригинального PoC-кода **TcbElevation** от [@splinter_code](https://github.com/splinter_code) и [@decoder_it](https://github.com/decoder_it), написанная для компиляции под Visual Studio 2022 на Windows 10 22H2 из-за невозможности скомпилировать оригинальный PoC.

Наличие привилегии `SeTcbPrivilege` в токене процесса позволяет добавить в новый токен произвольный SID (в данном случае SID SYSTEM) и получить выполнение кода в контексте **SYSTEM** без создания службы.

### Как это работает

0. Мы включаем привилегию SeTcbPrivilege через [Enable-Privilege.ps1](https://gist.github.com/anzz1/506ddfb17173e14709cba38dbd576f22).
1. Процесс открывает свой токен через `OpenProcessToken` и включает в него привилегию `SeTcbPrivilege` через `AdjustTokenPrivileges` (`EnableTokenPrivilege`).
2. Устанавливается недоверенное подключение к LSA через `LsaConnectUntrusted` и находится идентификатор пакета аутентификации MSV1_0 через `LsaLookupAuthenticationPackage`.
3. Формируется структура `MSV1_0_S4U_LOGON` с именем текущего пользователя и доменом `.` (локальная машина), после чего вызывается `LsaLogonUser` с типом входа `Network`.
4. В список групп нового токена добавляется SID `S-1-5-18` (NT AUTHORITY\SYSTEM) вместе с logon SID текущего пользователя. Наличие `SeTcbPrivilege` позволяет это сделать.
5. Токену выставляется средний уровень целостности (`TokenIntegrityLevel` = `S-1-16-8192`), чтобы избежать ограничений high-integrity контекста.
6. Выполняется `ImpersonateLoggedOnUser` — процесс получает контекст SYSTEM.
7. В имперсонированном контексте через `NetUserAdd` создаётся локальный пользователь, а через `NetLocalGroupAddMembers` он добавляется в группу `Administrators`.
8. Выполняется `RevertToSelf` для возврата в исходный контекст.

Стоит помнить, что это адаптация и некоторые параметры захардкожены, вам придётся менять их самостоятельно если вы используете код для другого окружения.

### Изменения с оригиналом

0. Вместо хука SSPI (`AcquireCredentialsHandleW`) с подменой LUID на `0x3E7` используется S4U-логин через `LsaLogonUser` с добавлением SID `S-1-5-18` в группы токена.
1. `wmain` без аргументов - целевой пользователь и пароль захардкожены.
2. `NetUserAdd` + `NetLocalGroupAddMembers` вместо `CreateService` + `StartService` с запуском cmd.
3. `EnableTokenPrivilege` без финальной проверки через `PrivilegeCheck` (в оригинале - `SetPrivilege` с проверкой).
4. Явная имперсонация через `ImpersonateLoggedOnUser` + `RevertToSelf` (в оригинале имперсонация неявная, через службу).
5. Добавлена работа с LSA: `LsaConnectUntrusted`, `LsaLookupAuthenticationPackage`, `LsaLogonUser`, `LsaDeregisterLogonProcess`.
6. Добавлена диагностика `DisplayTokenInformation` (статистика токена, группы, integrity level) и `GetLogonSID`.
7. Добавлена функция `InitUnicodeString` для ручной инициализации `UNICODE_STRING`.
8. Добавлен блок `Clear:` с освобождением SID, буферов, handle'ов и `LsaDeregisterLogonProcess`.
9. Изменены заголовки и библиотеки: добавлены `winternl.h`, `NTSecAPI.h`, `sddl.h`, `lm.h`, `Netapi32.lib`.

---

## Требования

- **Windows 10** (x64!!!)
- **Visual Studio 2022** с установленным workload `Desktop development with C++` (Platform Toolset v143)
- **Windows SDK 10**

## Использование

```cmd
C:\Temp> TcbPrivEsc.exe
[*] Initialize S4U login for user: svc_[REDACTED]
[*] LsaLogonUser succeeded
[*] Successfully impersonated token
[*] User 'drobilka' created successfully.
[*] User successfully added to Administrators group.
[*] Successfully created admin user 'drobilka'