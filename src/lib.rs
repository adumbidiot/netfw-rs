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
pub use skylight::oleauto::{
    BStr,
    BStrRef,
};
use std::{
    borrow::Cow,
    convert::TryFrom,
    ffi::OsStr,
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

pub trait IntoBStrArg<'a> {
    fn into_bstr_arg(self) -> Cow<'a, BStrRef>;
}

impl<'a> IntoBStrArg<'a> for &str {
    fn into_bstr_arg(self) -> Cow<'a, BStrRef> {
        BStr::new(self).into()
    }
}

impl<'a> IntoBStrArg<'a> for &OsStr {
    fn into_bstr_arg(self) -> Cow<'a, BStrRef> {
        BStr::new(self).into()
    }
}
