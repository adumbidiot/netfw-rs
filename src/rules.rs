use crate::{
    os_str_to_bstr,
    FirewallRule,
    FirewallRulesIter,
    VariantEnumerator,
};
use com::{
    interfaces::IUnknown,
    sys::FAILED,
};
use netfw_sys::INetFwRules;
use std::{
    ffi::OsStr,
    mem::MaybeUninit,
};
use winapi::um::oleauto::SysFreeString;

#[repr(transparent)]
pub struct FirewallRules(pub INetFwRules);

impl FirewallRules {
    pub fn get_count(&self) -> Result<usize, std::io::Error> {
        let mut count = 0;
        let ret = unsafe { self.0.get_count(&mut count) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else {
            Ok(count as usize)
        }
    }

    pub fn add(&self, rule: FirewallRule) -> Result<(), std::io::Error> {
        let ret = unsafe { self.0.add(rule.0) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else {
            Ok(())
        }
    }

    pub fn remove(&self, name: &OsStr) -> Result<(), std::io::Error> {
        let name = os_str_to_bstr(name);
        let ret = unsafe { self.0.remove(name) };
        unsafe { SysFreeString(name) }

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else {
            Ok(())
        }
    }

    pub fn get_enumerator(&self) -> Result<VariantEnumerator, std::io::Error> {
        let mut ptr = MaybeUninit::zeroed();
        let ret = unsafe { self.0.get_new_enum(ptr.as_mut_ptr()) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else {
            let unknown: IUnknown = unsafe { ptr.assume_init() };
            Ok(VariantEnumerator::from_raw(
                unknown.query_interface().expect("Valid IEnumVARIANT"),
            ))
        }
    }

    pub fn iter(&self) -> Result<FirewallRulesIter, std::io::Error> {
        Ok(FirewallRulesIter::new(self.get_enumerator()?))
    }
}

impl std::fmt::Debug for FirewallRules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut f = f.debug_struct("FirewallRules");

        if let Ok(count) = self.get_count() {
            f.field("count", &count);
        }

        f.finish()
    }
}

#[cfg(test)]
mod test {
    use crate::FirewallPolicy;
    use com::runtime::init_runtime;

    #[test]
    fn it_works() {
        init_runtime().unwrap();

        let firewall_policy = FirewallPolicy::new().unwrap();
        let firewall_rules = firewall_policy.get_rules().unwrap();

        dbg!(&firewall_rules);
        dbg!(firewall_rules.get_count().unwrap());
    }
}
