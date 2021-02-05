pub mod policy;
pub mod rule;
pub mod rules;

pub use self::{
    policy::FirewallPolicy,
    rule::FirewallRule,
    rules::FirewallRules,
};
use bitflags::bitflags;
use com::sys::FAILED;
use netfw_sys::{
    variant::VariantType,
    IEnumVARIANT,
    Variant,
    NET_FW_ACTION,
    NET_FW_ACTION_ALLOW,
    NET_FW_ACTION_BLOCK,
    NET_FW_ACTION_MAX,
    NET_FW_PROFILE2_ALL,
    NET_FW_PROFILE2_DOMAIN,
    NET_FW_PROFILE2_PRIVATE,
    NET_FW_PROFILE2_PUBLIC,
    NET_FW_PROFILE_TYPE2,
    NET_FW_RULE_DIRECTION,
    NET_FW_RULE_DIR_IN,
    NET_FW_RULE_DIR_MAX,
    NET_FW_RULE_DIR_OUT,
};
use std::{
    convert::TryFrom,
    ffi::{
        OsStr,
        OsString,
    },
    iter::once,
    os::windows::ffi::{
        OsStrExt,
        OsStringExt,
    },
};
use winapi::{
    shared::wtypes::BSTR,
    um::oleauto::SysAllocString,
};

bitflags! {
    pub struct FirewallProfile: NET_FW_PROFILE_TYPE2 {
        const DOMAIN = NET_FW_PROFILE2_DOMAIN;
        const PRIVATE = NET_FW_PROFILE2_PRIVATE;
        const PUBLIC = NET_FW_PROFILE2_PUBLIC;
        const ALL = NET_FW_PROFILE2_ALL;
    }
}

impl From<FirewallProfile> for NET_FW_PROFILE_TYPE2 {
    fn from(profile: FirewallProfile) -> Self {
        profile.bits()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FirewallAction {
    Block,
    Allow,
    Max,
}

impl From<FirewallAction> for NET_FW_ACTION {
    fn from(action: FirewallAction) -> Self {
        match action {
            FirewallAction::Block => NET_FW_ACTION_BLOCK,
            FirewallAction::Allow => NET_FW_ACTION_ALLOW,
            FirewallAction::Max => NET_FW_ACTION_MAX,
        }
    }
}

// NET_FW_ACTION is only a type-def, and I would rather have a fallible TryFrom for all u32s than a panicking From that may be called accidentally.
impl TryFrom<NET_FW_ACTION> for FirewallAction {
    type Error = NET_FW_ACTION;

    fn try_from(action: NET_FW_ACTION) -> Result<Self, Self::Error> {
        match action {
            NET_FW_ACTION_BLOCK => Ok(FirewallAction::Block),
            NET_FW_ACTION_ALLOW => Ok(FirewallAction::Allow),
            NET_FW_ACTION_MAX => Ok(FirewallAction::Max),
            _ => Err(action),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FirewallRuleDirection {
    In,
    Out,
    Max,
}

impl From<FirewallRuleDirection> for NET_FW_RULE_DIRECTION {
    fn from(dir: FirewallRuleDirection) -> Self {
        match dir {
            FirewallRuleDirection::In => NET_FW_RULE_DIR_IN,
            FirewallRuleDirection::Out => NET_FW_RULE_DIR_OUT,
            FirewallRuleDirection::Max => NET_FW_RULE_DIR_MAX,
        }
    }
}

// Same as above
impl TryFrom<NET_FW_RULE_DIRECTION> for FirewallRuleDirection {
    type Error = NET_FW_RULE_DIRECTION;

    fn try_from(action: NET_FW_RULE_DIRECTION) -> Result<Self, Self::Error> {
        match action {
            NET_FW_RULE_DIR_IN => Ok(FirewallRuleDirection::In),
            NET_FW_RULE_DIR_OUT => Ok(FirewallRuleDirection::Out),
            NET_FW_RULE_DIR_MAX => Ok(FirewallRuleDirection::Max),
            _ => Err(action),
        }
    }
}

// TODO: Consider just making a bstr type to avoid allocating an os string.
/// Panics if bstr is null or bstr data length in bytes is not a multiple of 2
/// # Safety
/// bstr must be a valid BSTR.
pub unsafe fn bstr_to_os_string(bstr: BSTR) -> OsString {
    assert!(!bstr.is_null(), "Null Pointer");

    let len_ptr = (bstr as *const u32).sub(1);
    let len_bytes = *len_ptr as usize;

    assert_eq!(len_bytes % 2, 0, "The byte len is not a multiple of 2");

    let slice = std::slice::from_raw_parts(bstr as *const u16, len_bytes / 2);

    OsString::from_wide(slice)
}

pub fn os_str_to_bstr(s: &OsStr) -> BSTR {
    let data: Vec<u16> = s.encode_wide().chain(once(0)).collect();
    let ptr = unsafe { SysAllocString(data.as_ptr()) };
    assert!(!ptr.is_null());
    ptr
}

#[repr(transparent)]
pub struct VariantEnumerator(IEnumVARIANT);

impl VariantEnumerator {
    pub fn from_raw(raw: IEnumVARIANT) -> Self {
        VariantEnumerator(raw)
    }

    pub fn next_one(&mut self) -> Result<Variant, std::io::Error> {
        let mut variant = Variant::new();

        let mut num_fetched = 0;
        let ret = unsafe { self.0.next(1, &mut variant, &mut num_fetched) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else {
            Ok(variant)
        }
    }

    pub fn next(&mut self, num: usize) -> Result<Vec<Variant>, std::io::Error> {
        let mut variants = Vec::with_capacity(num);

        let mut num_fetched = 0;
        let ret = unsafe {
            self.0
                .next(num as u32, variants.as_mut_ptr(), &mut num_fetched)
        };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else {
            unsafe { variants.set_len(num_fetched as usize) }
            Ok(variants)
        }
    }
}

#[repr(transparent)]
pub struct FirewallRulesIter(VariantEnumerator);

impl FirewallRulesIter {
    pub fn new(enumerator: VariantEnumerator) -> Self {
        FirewallRulesIter(enumerator)
    }
}

impl Iterator for FirewallRulesIter {
    type Item = Result<FirewallRule, std::io::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.0.next_one() {
            Ok(variant) => {
                if variant.variant_type() != VariantType::Empty {
                    let firewall = variant
                        .as_dispatch()
                        .expect("Valid IDispatch")
                        .query_interface()
                        .expect("Valid INetFwRule");

                    Some(Ok(FirewallRule(firewall)))
                } else {
                    None
                }
            }
            Err(e) => Some(Err(e)),
        }
    }
}
