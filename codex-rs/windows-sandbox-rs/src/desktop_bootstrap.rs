use crate::logging;
use crate::token::get_enabled_logon_sid_bytes;
use crate::winutil::to_wide;
use anyhow::Context;
use anyhow::Result;
use std::ffi::c_void;
use std::path::Path;
use std::path::PathBuf;
use std::ptr;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::HLOCAL;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Foundation::WAIT_ABANDONED;
use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
use windows_sys::Win32::Security::ACCESS_ALLOWED_ACE;
use windows_sys::Win32::Security::ACE_HEADER;
use windows_sys::Win32::Security::ACL;
use windows_sys::Win32::Security::ACL_REVISION;
use windows_sys::Win32::Security::ACL_SIZE_INFORMATION;
use windows_sys::Win32::Security::AccessCheck;
use windows_sys::Win32::Security::AclSizeInformation;
use windows_sys::Win32::Security::Authorization::GetSecurityInfo;
use windows_sys::Win32::Security::Authorization::SE_WINDOW_OBJECT;
use windows_sys::Win32::Security::Authorization::SetSecurityInfo;
use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
use windows_sys::Win32::Security::DuplicateToken;
use windows_sys::Win32::Security::GENERIC_MAPPING;
use windows_sys::Win32::Security::GROUP_SECURITY_INFORMATION;
use windows_sys::Win32::Security::GetAce;
use windows_sys::Win32::Security::GetAclInformation;
use windows_sys::Win32::Security::GetLengthSid;
use windows_sys::Win32::Security::InitializeAcl;
use windows_sys::Win32::Security::OWNER_SECURITY_INFORMATION;
use windows_sys::Win32::Security::PRIVILEGE_SET;
use windows_sys::Win32::Security::SecurityImpersonation;
use windows_sys::Win32::Security::TOKEN_DUPLICATE;
use windows_sys::Win32::Security::TOKEN_QUERY;
use windows_sys::Win32::System::StationsAndDesktops::GetProcessWindowStation;
use windows_sys::Win32::System::StationsAndDesktops::GetThreadDesktop;
use windows_sys::Win32::System::SystemServices::MAXIMUM_ALLOWED;
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::System::Threading::GetCurrentThreadId;
use windows_sys::Win32::System::Threading::INFINITE;
use windows_sys::Win32::System::Threading::OpenProcessToken;
use windows_sys::Win32::System::Threading::ReleaseMutex;
use windows_sys::Win32::System::Threading::WaitForSingleObject;

const BOOTSTRAP_ACL_MUTEX_NAME: &str = "Local\\CodexSandboxDesktopBootstrapAcl";
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const OBJECT_INHERIT_ACE: u8 = 0x01;
const CONTAINER_INHERIT_ACE: u8 = 0x02;
const INHERIT_ONLY_ACE: u8 = 0x08;
const INHERITED_ACE: u8 = 0x10;
const STANDARD_RIGHTS_READ: u32 = 0x0002_0000;
const STANDARD_RIGHTS_WRITE: u32 = 0x0002_0000;
const STANDARD_RIGHTS_EXECUTE: u32 = 0x0002_0000;
pub(crate) const SESSION0_LOGON_SID_WINDOW_STATION_INHERIT_MASK: u32 = 0xF000_0000;
pub(crate) const SESSION0_LOGON_SID_WINDOW_STATION_INHERIT_FLAGS: u8 =
    OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE;
pub(crate) const SESSION0_LOGON_SID_WINDOW_STATION_ACCESS: u32 = 0x000F_037F;
pub(crate) const SESSION0_LOGON_SID_DESKTOP_ACCESS: u32 = 0x000F_01FF;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowObjectKind {
    WindowStation,
    Desktop,
}

impl WindowObjectKind {
    fn name(self) -> &'static str {
        match self {
            Self::WindowStation => "window station",
            Self::Desktop => "desktop",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LogonSidGrantPlan {
    window_station: bool,
    desktop: bool,
}

impl LogonSidGrantPlan {
    #[cfg(test)]
    fn for_effective_access(window_station: u32, desktop: u32) -> Self {
        Self::for_effective_access_and_existing_grants(
            window_station,
            desktop,
            /*window_station_grant_exists*/ false,
            /*desktop_grant_exists*/ false,
        )
    }

    fn for_effective_access_and_existing_grants(
        window_station: u32,
        desktop: u32,
        window_station_grant_exists: bool,
        desktop_grant_exists: bool,
    ) -> Self {
        Self {
            // A byte-identical existing ACE may belong to another concurrent command. Add an
            // owned duplicate so exact-ACE multiplicity acts as a cross-process reference count.
            window_station: window_station != SESSION0_LOGON_SID_WINDOW_STATION_ACCESS
                || window_station_grant_exists,
            desktop: desktop != SESSION0_LOGON_SID_DESKTOP_ACCESS || desktop_grant_exists,
        }
    }

    fn ace_specs(self) -> Vec<LogonSidAceSpec> {
        let mut specs = Vec::with_capacity(3);
        if self.window_station {
            specs.extend([
                LogonSidAceSpec {
                    object: WindowObjectKind::WindowStation,
                    access_mask: SESSION0_LOGON_SID_WINDOW_STATION_INHERIT_MASK,
                    ace_flags: SESSION0_LOGON_SID_WINDOW_STATION_INHERIT_FLAGS,
                    description: "child logon-SID inheritable window-station",
                },
                LogonSidAceSpec {
                    object: WindowObjectKind::WindowStation,
                    access_mask: SESSION0_LOGON_SID_WINDOW_STATION_ACCESS,
                    ace_flags: 0,
                    description: "child logon-SID window-station",
                },
            ]);
        }
        if self.desktop {
            specs.push(LogonSidAceSpec {
                object: WindowObjectKind::Desktop,
                access_mask: SESSION0_LOGON_SID_DESKTOP_ACCESS,
                ace_flags: 0,
                description: "child logon-SID desktop",
            });
        }
        specs
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LogonSidAceSpec {
    object: WindowObjectKind,
    access_mask: u32,
    ace_flags: u8,
    description: &'static str,
}

/// Temporarily lets a newly created runner initialize on the caller's inherited window station
/// and desktop.
pub(crate) struct RunnerDesktopBootstrapAccess {
    grants: Vec<TemporaryWindowObjectAce>,
    logs_base_dir: Option<PathBuf>,
}

impl RunnerDesktopBootstrapAccess {
    pub(crate) fn new(logs_base_dir: Option<&Path>) -> Self {
        Self {
            grants: Vec::new(),
            logs_base_dir: logs_base_dir.map(Path::to_path_buf),
        }
    }

    /// Ensures and verifies the interactive logon-SID access masks for one suspended runner.
    pub(crate) fn grant_child_logon_sid(&mut self, process: HANDLE) -> Result<()> {
        let _mutex = NamedMutexGuard::acquire()
            .context("mutex failure: acquire runner desktop ACL mutex")?;
        let token = ProcessToken::open(process)
            .context("child-token/logon-SID extraction failure: open suspended runner token")?;
        let mut logon_sid = unsafe { get_enabled_logon_sid_bytes(token.handle) }
            .context("child-token/logon-SID extraction failure: extract enabled logon SID")?;
        let window_station = unsafe { GetProcessWindowStation() };
        anyhow::ensure!(
            window_station != 0,
            "DACL read failure: GetProcessWindowStation failed: {}",
            unsafe { GetLastError() }
        );
        let desktop = unsafe { GetThreadDesktop(GetCurrentThreadId()) };
        anyhow::ensure!(
            desktop != 0,
            "DACL read failure: GetThreadDesktop failed: {}",
            unsafe { GetLastError() }
        );

        let window_station_before = effective_access(
            window_station,
            token.handle,
            window_station_generic_mapping(),
            WindowObjectKind::WindowStation,
        )?;
        let desktop_before = effective_access(
            desktop,
            token.handle,
            desktop_generic_mapping(),
            WindowObjectKind::Desktop,
        )?;
        let sid = logon_sid.as_mut_ptr().cast();
        let window_station_grant_exists = [
            (
                SESSION0_LOGON_SID_WINDOW_STATION_INHERIT_MASK,
                SESSION0_LOGON_SID_WINDOW_STATION_INHERIT_FLAGS,
            ),
            (SESSION0_LOGON_SID_WINDOW_STATION_ACCESS, 0),
        ]
        .into_iter()
        .map(|(access_mask, ace_flags)| {
            contains_logon_sid_ace(
                window_station,
                WindowObjectKind::WindowStation,
                sid,
                access_mask,
                ace_flags,
            )
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .any(std::convert::identity);
        let desktop_grant_exists = contains_logon_sid_ace(
            desktop,
            WindowObjectKind::Desktop,
            sid,
            SESSION0_LOGON_SID_DESKTOP_ACCESS,
            /*ace_flags*/ 0,
        )?;
        let plan = LogonSidGrantPlan::for_effective_access_and_existing_grants(
            window_station_before,
            desktop_before,
            window_station_grant_exists,
            desktop_grant_exists,
        );
        for spec in plan.ace_specs() {
            let handle = match spec.object {
                WindowObjectKind::WindowStation => window_station,
                WindowObjectKind::Desktop => desktop,
            };
            self.add_owned_ace(
                handle,
                spec.object,
                sid,
                spec.access_mask,
                spec.ace_flags,
                spec.description,
            )?;
        }

        let window_station_after = effective_access(
            window_station,
            token.handle,
            window_station_generic_mapping(),
            WindowObjectKind::WindowStation,
        )?;
        let desktop_after = effective_access(
            desktop,
            token.handle,
            desktop_generic_mapping(),
            WindowObjectKind::Desktop,
        )?;
        anyhow::ensure!(
            window_station_after == SESSION0_LOGON_SID_WINDOW_STATION_ACCESS,
            "exact-mask verification failure for window station: effective access was 0x{window_station_after:08X}, expected exactly 0x{SESSION0_LOGON_SID_WINDOW_STATION_ACCESS:08X}"
        );
        anyhow::ensure!(
            desktop_after == SESSION0_LOGON_SID_DESKTOP_ACCESS,
            "exact-mask verification failure for desktop: effective access was 0x{desktop_after:08X}, expected exactly 0x{SESSION0_LOGON_SID_DESKTOP_ACCESS:08X}"
        );
        Ok(())
    }

    fn add_owned_ace(
        &mut self,
        handle: HANDLE,
        object: WindowObjectKind,
        sid: *mut c_void,
        access_mask: u32,
        ace_flags: u8,
        description: &'static str,
    ) -> Result<()> {
        let grant = TemporaryWindowObjectAce::grant(
            handle,
            object,
            sid,
            access_mask,
            ace_flags,
            description,
        )
        .with_context(|| format!("ACE insertion failure: {description}"))?;
        self.grants.push(grant);
        Ok(())
    }

    pub(crate) fn revoke(mut self) -> Result<()> {
        self.cleanup()
    }

    fn cleanup(&mut self) -> Result<()> {
        let _mutex = NamedMutexGuard::acquire()
            .context("mutex failure: acquire runner desktop ACL mutex for cleanup")?;
        let mut errors = Vec::new();
        while let Some(mut grant) = self.grants.pop() {
            if let Err(err) = grant.revoke() {
                errors.push(format!("{err:#}"));
            }
        }
        if !errors.is_empty() {
            anyhow::bail!(
                "cleanup/ownership accounting failure: failed to remove runner window-object ACEs: {}",
                errors.join("; ")
            );
        }
        Ok(())
    }
}

impl Drop for RunnerDesktopBootstrapAccess {
    fn drop(&mut self) {
        if let Err(err) = self.cleanup() {
            logging::debug_log(
                &format!("failed to remove runner desktop bootstrap access: {err:#}"),
                self.logs_base_dir.as_deref(),
            );
        }
    }
}

struct ProcessToken {
    handle: HANDLE,
}

impl ProcessToken {
    fn open(process: HANDLE) -> Result<Self> {
        let mut handle = 0;
        if unsafe { OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &mut handle) } == 0 {
            anyhow::bail!("OpenProcessToken(suspended runner) failed: {}", unsafe {
                GetLastError()
            });
        }
        Ok(Self { handle })
    }
}

impl Drop for ProcessToken {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

fn effective_access(
    handle: HANDLE,
    primary_token: HANDLE,
    mapping: GENERIC_MAPPING,
    object: WindowObjectKind,
) -> Result<u32> {
    let mut security_descriptor = ptr::null_mut();
    let mut owner = ptr::null_mut();
    let mut group = ptr::null_mut();
    let get_code = unsafe {
        GetSecurityInfo(
            handle,
            SE_WINDOW_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            &mut group,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut security_descriptor,
        )
    };
    if get_code != ERROR_SUCCESS {
        anyhow::bail!(
            "DACL read failure for {}: GetSecurityInfo returned {get_code}",
            object.name()
        );
    }

    let result = (|| {
        let mut impersonation_token = 0;
        if unsafe {
            DuplicateToken(
                primary_token,
                SecurityImpersonation,
                &mut impersonation_token,
            )
        } == 0
        {
            anyhow::bail!(
                "AccessCheck failure for {}: DuplicateToken returned {}",
                object.name(),
                unsafe { GetLastError() }
            );
        }
        let token = ProcessToken {
            handle: impersonation_token,
        };
        access_check(security_descriptor, token.handle, mapping)
            .with_context(|| format!("AccessCheck failure for {}", object.name()))
    })();
    unsafe {
        LocalFree(security_descriptor as HLOCAL);
    }
    result
}

fn access_check(
    security_descriptor: *mut c_void,
    token: HANDLE,
    mapping: GENERIC_MAPPING,
) -> Result<u32> {
    let mut storage = vec![0usize; 64];
    loop {
        let storage_bytes = storage.len() * std::mem::size_of::<usize>();
        let mut privilege_length = u32::try_from(storage_bytes)
            .context("AccessCheck privilege-set buffer is too large")?;
        let mut granted = 0;
        let mut access_status = 0;
        let ok = unsafe {
            AccessCheck(
                security_descriptor,
                token,
                MAXIMUM_ALLOWED,
                &mapping,
                storage.as_mut_ptr().cast::<PRIVILEGE_SET>(),
                &mut privilege_length,
                &mut granted,
                &mut access_status,
            )
        };
        if ok != 0 {
            return Ok(access_check_granted_mask(access_status, granted));
        }
        let error = unsafe { GetLastError() };
        if error != ERROR_INSUFFICIENT_BUFFER || privilege_length as usize <= storage_bytes {
            anyhow::bail!("AccessCheck failed: {error}");
        }
        anyhow::ensure!(
            privilege_length <= 64 * 1024,
            "AccessCheck requested an unexpectedly large privilege-set buffer: {privilege_length} bytes"
        );
        storage.resize(
            (privilege_length as usize).div_ceil(std::mem::size_of::<usize>()),
            0,
        );
    }
}

fn access_check_granted_mask(access_status: i32, granted: u32) -> u32 {
    if access_status == 0 { 0 } else { granted }
}

fn window_station_generic_mapping() -> GENERIC_MAPPING {
    GENERIC_MAPPING {
        GenericRead: STANDARD_RIGHTS_READ | 0x0001 | 0x0002 | 0x0100 | 0x0200,
        GenericWrite: STANDARD_RIGHTS_WRITE | 0x0004 | 0x0008 | 0x0010,
        GenericExecute: STANDARD_RIGHTS_EXECUTE | 0x0020 | 0x0040,
        GenericAll: SESSION0_LOGON_SID_WINDOW_STATION_ACCESS,
    }
}

fn desktop_generic_mapping() -> GENERIC_MAPPING {
    GENERIC_MAPPING {
        GenericRead: STANDARD_RIGHTS_READ | 0x0001 | 0x0040,
        GenericWrite: STANDARD_RIGHTS_WRITE | 0x0002 | 0x0004 | 0x0008 | 0x0010 | 0x0020 | 0x0080,
        GenericExecute: STANDARD_RIGHTS_EXECUTE | 0x0100,
        GenericAll: SESSION0_LOGON_SID_DESKTOP_ACCESS,
    }
}

struct NamedMutexGuard {
    handle: HANDLE,
}

impl NamedMutexGuard {
    fn acquire() -> Result<Self> {
        let name = to_wide(BOOTSTRAP_ACL_MUTEX_NAME);
        // Serialize only each read-modify-write transaction. Ownership of exact inserted ACEs is
        // long-lived, but holding this mutex for a runner's lifetime would serialize all sandbox
        // work in the session.
        let handle = unsafe {
            CreateMutexW(ptr::null_mut(), /*binitialowner*/ 0, name.as_ptr())
        };
        if handle == 0 {
            anyhow::bail!("CreateMutexW failed for runner desktop ACL: {}", unsafe {
                GetLastError()
            });
        }
        let wait = unsafe { WaitForSingleObject(handle, INFINITE) };
        if wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED {
            unsafe {
                CloseHandle(handle);
            }
            anyhow::bail!("WaitForSingleObject failed for runner desktop ACL: {wait}");
        }
        Ok(Self { handle })
    }
}

impl Drop for NamedMutexGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = ReleaseMutex(self.handle);
            CloseHandle(self.handle);
        }
    }
}

struct TemporaryWindowObjectAce {
    handle: HANDLE,
    object: WindowObjectKind,
    ace: Vec<u8>,
    active: bool,
    description: &'static str,
}

impl TemporaryWindowObjectAce {
    fn grant(
        handle: HANDLE,
        object: WindowObjectKind,
        sid: *mut c_void,
        access_mask: u32,
        ace_flags: u8,
        description: &'static str,
    ) -> Result<Self> {
        let ace = access_allowed_ace(sid, access_mask, ace_flags)
            .with_context(|| format!("build {description} ACE"))?;
        let active = update_dacl(handle, object, |dacl| acl_with_added_ace(dacl, &ace))?;
        let grant = Self {
            handle,
            object,
            ace,
            active,
            description,
        };
        if active {
            let verification = dacl_contains_exact_ace(handle, object, &grant.ace);
            let verification_error = match verification {
                Ok(Some(true)) => None,
                Ok(_) => Some(anyhow::anyhow!(
                    "ACE insertion failure: {description} ACE was not present after SetSecurityInfo"
                )),
                Err(err) => Some(err),
            };
            if let Some(verification_error) = verification_error {
                let mut grant = grant;
                if let Err(cleanup_error) = grant.revoke() {
                    return Err(anyhow::anyhow!(
                        "{verification_error:#}; rollback after ACE verification failure also failed: {cleanup_error:#}"
                    ));
                }
                return Err(verification_error);
            }
        }
        Ok(grant)
    }

    fn revoke(&mut self) -> Result<()> {
        if self.active {
            let removed = update_dacl(self.handle, self.object, |dacl| {
                acl_without_matching_ace(dacl, &self.ace)
            })?;
            anyhow::ensure!(
                removed,
                "cleanup/ownership accounting failure: owned {} ACE was not present on the latest {} DACL",
                self.description,
                self.object.name()
            );
            self.active = false;
        }
        Ok(())
    }
}

fn dacl_contains_exact_ace(
    handle: HANDLE,
    object: WindowObjectKind,
    expected_ace: &[u8],
) -> Result<Option<bool>> {
    let mut security_descriptor = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let get_code = unsafe {
        GetSecurityInfo(
            handle,
            SE_WINDOW_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut security_descriptor,
        )
    };
    if get_code != ERROR_SUCCESS {
        anyhow::bail!(
            "DACL read failure for {} while verifying inserted ACE: GetSecurityInfo returned {get_code}",
            object.name()
        );
    }

    let result = (|| {
        if dacl.is_null() {
            Ok(None)
        } else {
            Ok(Some(
                acl_aces(dacl)?
                    .iter()
                    .any(|candidate| candidate == expected_ace),
            ))
        }
    })();
    unsafe {
        LocalFree(security_descriptor as HLOCAL);
    }
    result
}

fn contains_logon_sid_ace(
    handle: HANDLE,
    object: WindowObjectKind,
    sid: *mut c_void,
    access_mask: u32,
    ace_flags: u8,
) -> Result<bool> {
    let ace = access_allowed_ace(sid, access_mask, ace_flags)?;
    Ok(dacl_contains_exact_ace(handle, object, &ace)?.unwrap_or(false))
}

impl Drop for TemporaryWindowObjectAce {
    fn drop(&mut self) {
        let _ = self.revoke();
    }
}

fn update_dacl(
    handle: HANDLE,
    object: WindowObjectKind,
    update: impl FnOnce(*mut ACL) -> Result<Option<Vec<u8>>>,
) -> Result<bool> {
    let mut security_descriptor = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let get_code = unsafe {
        GetSecurityInfo(
            handle,
            SE_WINDOW_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut security_descriptor,
        )
    };
    if get_code != ERROR_SUCCESS {
        anyhow::bail!(
            "DACL read failure for {}: GetSecurityInfo returned {get_code}",
            object.name()
        );
    }

    let result = (|| {
        let Some(mut updated_dacl) = update(dacl)? else {
            return Ok(false);
        };
        let set_code = unsafe {
            SetSecurityInfo(
                handle,
                SE_WINDOW_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                updated_dacl.as_mut_ptr().cast(),
                ptr::null_mut(),
            )
        };
        if set_code != ERROR_SUCCESS {
            anyhow::bail!("SetSecurityInfo failed for {}: {set_code}", object.name());
        }
        Ok(true)
    })();

    unsafe {
        LocalFree(security_descriptor as HLOCAL);
    }
    result
}

fn access_allowed_ace(sid: *mut c_void, access_mask: u32, ace_flags: u8) -> Result<Vec<u8>> {
    let sid_len = unsafe { GetLengthSid(sid) } as usize;
    if sid_len == 0 {
        anyhow::bail!("GetLengthSid failed: {}", unsafe { GetLastError() });
    }
    let ace_len = std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        .checked_sub(std::mem::size_of::<u32>())
        .and_then(|len| len.checked_add(sid_len))
        .context("runner desktop ACE size overflow")?;
    let ace_len_u16 = u16::try_from(ace_len).context("runner desktop ACE is too large")?;
    let mut ace = vec![0u8; ace_len];
    unsafe {
        let header = ace.as_mut_ptr().cast::<ACE_HEADER>();
        (*header).AceType = ACCESS_ALLOWED_ACE_TYPE;
        (*header).AceFlags = ace_flags;
        (*header).AceSize = ace_len_u16;
        let allowed = ace.as_mut_ptr().cast::<ACCESS_ALLOWED_ACE>();
        (*allowed).Mask = access_mask;
        ptr::copy_nonoverlapping(
            sid.cast::<u8>(),
            (&mut (*allowed).SidStart as *mut u32).cast::<u8>(),
            sid_len,
        );
    }
    Ok(ace)
}

fn acl_with_added_ace(dacl: *mut ACL, ace: &[u8]) -> Result<Option<Vec<u8>>> {
    // A null DACL already grants full access, so changing it would only weaken cleanup behavior.
    if dacl.is_null() {
        return Ok(None);
    }
    rebuild_acl(dacl, Some(ace), None).map(Some)
}

fn acl_without_matching_ace(dacl: *mut ACL, ace: &[u8]) -> Result<Option<Vec<u8>>> {
    if dacl.is_null() {
        return Ok(None);
    }
    let aces = acl_aces(dacl)?;
    // `grant` inserts immediately before inherited ACEs, so the last exact explicit match is the
    // instance this guard added. An uncooperating actor that inserts a byte-identical ACE during
    // the guarded lifetime is inherently indistinguishable; removing one exact instance still
    // preserves the preexisting count and every non-identical concurrent mutation.
    let Some(ace_index) = aces.iter().rposition(|candidate| candidate == ace) else {
        return Ok(None);
    };
    rebuild_acl_from_aces(dacl, &aces, None, Some(ace_index)).map(Some)
}

fn rebuild_acl(
    dacl: *mut ACL,
    added_ace: Option<&[u8]>,
    removed_ace: Option<usize>,
) -> Result<Vec<u8>> {
    let aces = acl_aces(dacl)?;
    rebuild_acl_from_aces(dacl, &aces, added_ace, removed_ace)
}

fn rebuild_acl_from_aces(
    dacl: *mut ACL,
    aces: &[Vec<u8>],
    added_ace: Option<&[u8]>,
    removed_ace: Option<usize>,
) -> Result<Vec<u8>> {
    let added_len = added_ace.map_or(0, <[u8]>::len);
    let removed_len = removed_ace.map_or(0, |index| aces[index].len());
    let acl_len = std::mem::size_of::<ACL>()
        .checked_add(aces.iter().map(Vec::len).sum::<usize>())
        .and_then(|len| len.checked_add(added_len))
        .and_then(|len| len.checked_sub(removed_len))
        .context("runner desktop ACL size overflow")?;
    let acl_len_u32 = u32::try_from(acl_len).context("runner desktop ACL is too large")?;
    let revision = unsafe { u32::from((*dacl).AclRevision.max(ACL_REVISION as u8)) };
    let mut rebuilt = vec![0u8; acl_len];
    if unsafe { InitializeAcl(rebuilt.as_mut_ptr().cast(), acl_len_u32, revision) } == 0 {
        anyhow::bail!("InitializeAcl failed: {}", unsafe { GetLastError() });
    }

    let insertion_index = aces
        .iter()
        .position(|ace| ace[1] & INHERITED_ACE != 0)
        .unwrap_or(aces.len());
    for index in 0..=aces.len() {
        if let Some(added_ace) = added_ace.filter(|_| index == insertion_index) {
            add_ace(&mut rebuilt, revision, added_ace)?;
        }
        if index < aces.len() && removed_ace != Some(index) {
            add_ace(&mut rebuilt, revision, &aces[index])?;
        }
    }
    Ok(rebuilt)
}

fn add_ace(acl: &mut [u8], revision: u32, ace: &[u8]) -> Result<()> {
    if unsafe {
        windows_sys::Win32::Security::AddAce(
            acl.as_mut_ptr().cast(),
            revision,
            u32::MAX,
            ace.as_ptr().cast(),
            ace.len() as u32,
        )
    } == 0
    {
        anyhow::bail!("AddAce failed: {}", unsafe { GetLastError() });
    }
    Ok(())
}

fn acl_aces(dacl: *mut ACL) -> Result<Vec<Vec<u8>>> {
    let mut info: ACL_SIZE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe {
        GetAclInformation(
            dacl.cast_const(),
            (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        anyhow::bail!("GetAclInformation failed: {}", unsafe { GetLastError() });
    }
    let mut aces = Vec::with_capacity(info.AceCount as usize);
    for index in 0..info.AceCount {
        let mut ace = ptr::null_mut();
        if unsafe { GetAce(dacl.cast_const(), index, &mut ace) } == 0 {
            anyhow::bail!("GetAce failed: {}", unsafe { GetLastError() });
        }
        let ace_len = unsafe { usize::from((*ace.cast::<ACE_HEADER>()).AceSize) };
        aces.push(unsafe { std::slice::from_raw_parts(ace.cast::<u8>(), ace_len) }.to_vec());
    }
    Ok(aces)
}

#[cfg(test)]
#[path = "desktop_bootstrap_tests.rs"]
mod tests;
