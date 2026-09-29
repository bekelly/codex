use super::LogonSidAceSpec;
use super::LogonSidGrantPlan;
use super::SESSION0_LOGON_SID_DESKTOP_ACCESS;
use super::SESSION0_LOGON_SID_WINDOW_STATION_ACCESS;
use super::SESSION0_LOGON_SID_WINDOW_STATION_INHERIT_FLAGS;
use super::SESSION0_LOGON_SID_WINDOW_STATION_INHERIT_MASK;
use super::WindowObjectKind;
use super::access_allowed_ace;
use super::access_check_granted_mask;
use super::acl_aces;
use super::acl_with_added_ace;
use super::acl_without_matching_ace;
use crate::token::get_current_token_for_restriction;
use crate::token::get_enabled_logon_sid_bytes;
use crate::token::get_user_sid_bytes;
use crate::winutil::string_from_sid_bytes;
use pretty_assertions::assert_eq;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Security::ACL;
use windows_sys::Win32::Security::ACL_REVISION;
use windows_sys::Win32::Security::InitializeAcl;

fn empty_acl() -> Vec<u8> {
    let mut acl = vec![0u8; std::mem::size_of::<ACL>()];
    assert_ne!(
        unsafe { InitializeAcl(acl.as_mut_ptr().cast(), acl.len() as u32, ACL_REVISION) },
        0
    );
    acl
}

fn current_user_sid() -> anyhow::Result<Vec<u8>> {
    let token = unsafe { get_current_token_for_restriction()? };
    let sid = unsafe { get_user_sid_bytes(token) };
    unsafe {
        CloseHandle(token);
    }
    sid
}

#[test]
fn required_access_already_present_plans_no_addition_or_removal() -> anyhow::Result<()> {
    let mut sid = current_user_sid()?;
    let preexisting = access_allowed_ace(sid.as_mut_ptr().cast(), 0x01, /*ace_flags*/ 0)?;
    let mut acl = empty_acl();
    acl = acl_with_added_ace(acl.as_mut_ptr().cast(), &preexisting)?.unwrap();
    let original_acl = acl.clone();

    let plan = LogonSidGrantPlan::for_effective_access(
        SESSION0_LOGON_SID_WINDOW_STATION_ACCESS,
        SESSION0_LOGON_SID_DESKTOP_ACCESS,
    );
    let owned_aces = plan.ace_specs();

    assert_eq!(owned_aces, Vec::<LogonSidAceSpec>::new());
    assert_eq!(acl, original_acl);
    Ok(())
}

#[test]
fn maximum_allowed_denial_reports_zero_effective_access() {
    assert_eq!(access_check_granted_mask(/*access_status*/ 0, 0), 0);
}

#[test]
fn zero_baseline_access_plans_every_required_logon_sid_ace() {
    assert_eq!(
        LogonSidGrantPlan::for_effective_access(0, 0).ace_specs(),
        vec![
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
            LogonSidAceSpec {
                object: WindowObjectKind::Desktop,
                access_mask: SESSION0_LOGON_SID_DESKTOP_ACCESS,
                ace_flags: 0,
                description: "child logon-SID desktop",
            },
        ]
    );
}

#[test]
fn concurrent_grant_reuse_plans_an_owned_duplicate() {
    assert_eq!(
        LogonSidGrantPlan::for_effective_access_and_existing_grants(
            SESSION0_LOGON_SID_WINDOW_STATION_ACCESS,
            SESSION0_LOGON_SID_DESKTOP_ACCESS,
            /*window_station_grant_exists*/ true,
            /*desktop_grant_exists*/ true,
        )
        .ace_specs(),
        LogonSidGrantPlan::for_effective_access(0, 0).ace_specs()
    );
}

#[test]
fn partial_access_plans_aces_only_for_the_insufficient_object() {
    let desktop_only =
        LogonSidGrantPlan::for_effective_access(SESSION0_LOGON_SID_WINDOW_STATION_ACCESS, 0x83);
    assert_eq!(
        desktop_only.ace_specs(),
        vec![LogonSidAceSpec {
            object: WindowObjectKind::Desktop,
            access_mask: SESSION0_LOGON_SID_DESKTOP_ACCESS,
            ace_flags: 0,
            description: "child logon-SID desktop",
        }]
    );

    let window_station_only =
        LogonSidGrantPlan::for_effective_access(0x22, SESSION0_LOGON_SID_DESKTOP_ACCESS);
    assert_eq!(
        window_station_only.ace_specs(),
        vec![
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
        ]
    );
}

#[test]
fn newly_added_ace_is_removed() -> anyhow::Result<()> {
    let mut sid = current_user_sid()?;
    let temporary = access_allowed_ace(sid.as_mut_ptr().cast(), 0x02, /*ace_flags*/ 0)?;

    let mut acl = empty_acl();
    acl = acl_with_added_ace(acl.as_mut_ptr().cast(), &temporary)?.unwrap();
    let final_acl = acl_without_matching_ace(acl.as_mut_ptr().cast(), &temporary)?.unwrap();

    assert_eq!(
        acl_aces(final_acl.as_ptr() as *mut ACL)?,
        Vec::<Vec<u8>>::new()
    );
    Ok(())
}

#[test]
fn cleanup_preserves_concurrent_unrelated_dacl_mutation() -> anyhow::Result<()> {
    let mut sid = current_user_sid()?;
    let first = access_allowed_ace(sid.as_mut_ptr().cast(), 0x01, /*ace_flags*/ 0)?;
    let temporary = access_allowed_ace(sid.as_mut_ptr().cast(), 0x02, /*ace_flags*/ 0)?;
    let later = access_allowed_ace(sid.as_mut_ptr().cast(), 0x04, /*ace_flags*/ 0)?;

    let mut acl = empty_acl();
    acl = acl_with_added_ace(acl.as_mut_ptr().cast(), &first)?.unwrap();
    acl = acl_with_added_ace(acl.as_mut_ptr().cast(), &temporary)?.unwrap();
    acl = acl_with_added_ace(acl.as_mut_ptr().cast(), &later)?.unwrap();
    let final_acl = acl_without_matching_ace(acl.as_mut_ptr().cast(), &temporary)?.unwrap();

    assert_eq!(
        acl_aces(final_acl.as_ptr() as *mut ACL)?,
        vec![first, later]
    );
    Ok(())
}

#[test]
fn cleanup_preserves_preexisting_byte_identical_ace() -> anyhow::Result<()> {
    let mut sid = current_user_sid()?;
    let identical = access_allowed_ace(sid.as_mut_ptr().cast(), 0x02, /*ace_flags*/ 0)?;
    let unrelated = access_allowed_ace(sid.as_mut_ptr().cast(), 0x04, /*ace_flags*/ 0)?;

    let mut acl = empty_acl();
    acl = acl_with_added_ace(acl.as_mut_ptr().cast(), &identical)?.unwrap();
    acl = acl_with_added_ace(acl.as_mut_ptr().cast(), &identical)?.unwrap();
    acl = acl_with_added_ace(acl.as_mut_ptr().cast(), &unrelated)?.unwrap();
    let final_acl = acl_without_matching_ace(acl.as_mut_ptr().cast(), &identical)?.unwrap();

    assert_eq!(
        acl_aces(final_acl.as_ptr() as *mut ACL)?,
        vec![identical, unrelated]
    );
    Ok(())
}

#[test]
fn extracts_enabled_logon_sid_from_real_token() -> anyhow::Result<()> {
    let token = unsafe { get_current_token_for_restriction()? };
    let sid = unsafe { get_enabled_logon_sid_bytes(token)? };
    unsafe {
        CloseHandle(token);
    }

    assert!(
        string_from_sid_bytes(&sid)
            .map_err(anyhow::Error::msg)?
            .starts_with("S-1-5-5-")
    );
    Ok(())
}
