use crate::{
    FirewallAction,
    FirewallProfile,
    FirewallRuleDirection,
    IntoBStrArg,
};
use com::{
    runtime::create_instance,
    sys::FAILED,
};
use netfw_sys::{
    variant::VariantType,
    INetFwRule,
    Variant,
    CLSID_INETFWRULE,
    NET_FW_ACTION,
    NET_FW_RULE_DIRECTION,
};
use skylight::oleauto::BStr;
use std::convert::TryFrom;
use winapi::{
    shared::wtypes::{
        VARIANT_FALSE,
        VARIANT_TRUE,
    },
    um::winnt::LONG,
};

#[repr(transparent)]
pub struct FirewallRule(pub INetFwRule);

impl FirewallRule {
    pub fn new() -> Result<Self, std::io::Error> {
        create_instance::<INetFwRule>(&CLSID_INETFWRULE)
            .map(FirewallRule)
            .map_err(std::io::Error::from_raw_os_error)
    }

    pub fn get_name(&self) -> Result<BStr, std::io::Error> {
        let mut bstr = std::ptr::null_mut();
        let ret = unsafe { self.0.get_name(&mut bstr) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else {
            Ok(unsafe { BStr::from_raw(bstr) })
        }
    }

    pub fn set_name<'a>(&self, name: impl IntoBStrArg<'a>) -> Result<(), std::io::Error> {
        let ret = unsafe { self.0.put_name(name.into_bstr_arg().as_ptr() as *mut u16) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else {
            Ok(())
        }
    }

    pub fn get_description(&self) -> Result<Option<BStr>, std::io::Error> {
        let mut bstr = std::ptr::null_mut();
        let ret = unsafe { self.0.get_description(&mut bstr) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else if bstr.is_null() {
            Ok(None)
        } else {
            Ok(Some(unsafe { BStr::from_raw(bstr) }))
        }
    }

    pub fn get_application_name(&self) -> Result<Option<BStr>, std::io::Error> {
        let mut bstr = std::ptr::null_mut();
        let ret = unsafe { self.0.get_application_name(&mut bstr) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else if bstr.is_null() {
            Ok(None)
        } else {
            Ok(Some(unsafe { BStr::from_raw(bstr) }))
        }
    }

    pub fn set_application_name<'a>(
        &self,
        name: impl IntoBStrArg<'a>,
    ) -> Result<(), std::io::Error> {
        let ret = unsafe {
            self.0
                .put_application_name(name.into_bstr_arg().as_ptr() as *mut u16)
        };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else {
            Ok(())
        }
    }

    pub fn get_service_name(&self) -> Result<Option<BStr>, std::io::Error> {
        let mut bstr = std::ptr::null_mut();
        let ret = unsafe { self.0.get_service_name(&mut bstr) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else if bstr.is_null() {
            Ok(None)
        } else {
            Ok(Some(unsafe { BStr::from_raw(bstr) }))
        }
    }

    pub fn get_protocol(&self) -> Result<LONG, std::io::Error> {
        let mut protocol = 0;
        let ret = unsafe { self.0.get_protocol(&mut protocol) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else {
            Ok(protocol)
        }
    }

    pub fn get_local_ports(&self) -> Result<Option<BStr>, std::io::Error> {
        let mut bstr = std::ptr::null_mut();
        let ret = unsafe { self.0.get_local_ports(&mut bstr) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else if bstr.is_null() {
            Ok(None)
        } else {
            Ok(Some(unsafe { BStr::from_raw(bstr) }))
        }
    }

    pub fn get_remote_ports(&self) -> Result<Option<BStr>, std::io::Error> {
        let mut bstr = std::ptr::null_mut();
        let ret = unsafe { self.0.get_remote_ports(&mut bstr) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else if bstr.is_null() {
            Ok(None)
        } else {
            Ok(Some(unsafe { BStr::from_raw(bstr) }))
        }
    }

    pub fn get_local_addresses(&self) -> Result<Option<BStr>, std::io::Error> {
        let mut bstr = std::ptr::null_mut();
        let ret = unsafe { self.0.get_local_addresses(&mut bstr) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else if bstr.is_null() {
            Ok(None)
        } else {
            Ok(Some(unsafe { BStr::from_raw(bstr) }))
        }
    }

    pub fn get_remote_addresses(&self) -> Result<Option<BStr>, std::io::Error> {
        let mut bstr = std::ptr::null_mut();
        let ret = unsafe { self.0.get_remote_addresses(&mut bstr) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else if bstr.is_null() {
            Ok(None)
        } else {
            Ok(Some(unsafe { BStr::from_raw(bstr) }))
        }
    }

    pub fn set_remote_addresses<'a>(
        &self,
        name: impl IntoBStrArg<'a>,
    ) -> Result<(), std::io::Error> {
        let ret = unsafe {
            self.0
                .put_remote_addresses(name.into_bstr_arg().as_ptr() as *mut u16)
        };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else {
            Ok(())
        }
    }

    pub fn get_icmp_types_and_codes(&self) -> Result<Option<BStr>, std::io::Error> {
        let mut bstr = std::ptr::null_mut();
        let ret = unsafe { self.0.get_icmp_types_and_codes(&mut bstr) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else if bstr.is_null() {
            Ok(None)
        } else {
            Ok(Some(unsafe { BStr::from_raw(bstr) }))
        }
    }

    pub fn get_direction(&self) -> Result<FirewallRuleDirection, std::io::Error> {
        let mut dir = 0;
        let ret = unsafe { self.0.get_direction(&mut dir) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else {
            Ok(FirewallRuleDirection::try_from(dir).expect("Valid NET_FW_RULE_DIRECTION"))
        }
    }

    pub fn set_direction(&self, dir: FirewallRuleDirection) -> Result<(), std::io::Error> {
        let dir: NET_FW_RULE_DIRECTION = dir.into();
        let ret = unsafe { self.0.put_direction(dir) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else {
            Ok(())
        }
    }

    pub fn get_interfaces(&self) -> Result<Option<Vec<BStr>>, std::io::Error> {
        let mut variant = Variant::new();
        let ret = unsafe { self.0.get_interfaces(&mut variant) };

        if FAILED(ret) {
            return Err(std::io::Error::from_raw_os_error(ret));
        }

        if variant.variant_type() == VariantType::Empty {
            return Ok(None);
        }

        let array = variant.as_array().expect("Variant Array");
        let lower_bound = array.lower_bound();
        let upper_bound = lower_bound + array.len();
        let range = lower_bound as i32..upper_bound as i32;

        let mut ret = Vec::with_capacity(upper_bound - lower_bound);

        for i in range {
            let data: Variant = unsafe { array.get(&[i]).expect("Valid Index") };
            let bstr = data.as_bstr().expect("Variant Bstr");

            ret.push(unsafe { BStr::from_raw(bstr) });
        }

        Ok(Some(ret))
    }

    pub fn get_interface_types(&self) -> Result<Option<BStr>, std::io::Error> {
        let mut bstr = std::ptr::null_mut();
        let ret = unsafe { self.0.get_interface_types(&mut bstr) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else if bstr.is_null() {
            Ok(None)
        } else {
            Ok(Some(unsafe { BStr::from_raw(bstr) }))
        }
    }

    pub fn get_enabled(&self) -> Result<bool, std::io::Error> {
        let mut enabled = VARIANT_FALSE;
        let ret = unsafe { self.0.get_enabled(&mut enabled) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else {
            Ok(enabled == VARIANT_TRUE)
        }
    }

    pub fn set_enabled(&self, enabled: bool) -> Result<(), std::io::Error> {
        let enabled = if enabled { VARIANT_TRUE } else { VARIANT_FALSE };
        let ret = unsafe { self.0.put_enabled(enabled) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else {
            Ok(())
        }
    }

    pub fn get_grouping(&self) -> Result<Option<BStr>, std::io::Error> {
        let mut bstr = std::ptr::null_mut();
        let ret = unsafe { self.0.get_grouping(&mut bstr) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else if bstr.is_null() {
            Ok(None)
        } else {
            Ok(Some(unsafe { BStr::from_raw(bstr) }))
        }
    }

    pub fn get_profiles(&self) -> Result<FirewallProfile, std::io::Error> {
        let mut profiles = 0;
        let ret = unsafe { self.0.get_profiles(&mut profiles) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else {
            Ok(FirewallProfile::from_bits_truncate(profiles as u32))
        }
    }

    pub fn get_edge_traversal(&self) -> Result<bool, std::io::Error> {
        let mut enabled = VARIANT_FALSE;
        let ret = unsafe { self.0.get_edge_traversal(&mut enabled) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else {
            Ok(enabled == VARIANT_TRUE)
        }
    }

    pub fn get_action(&self) -> Result<FirewallAction, std::io::Error> {
        let mut action = 0;
        let ret = unsafe { self.0.get_action(&mut action) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else {
            Ok(FirewallAction::try_from(action).expect("Valid NET_FW_ACTION"))
        }
    }

    pub fn set_action(&self, action: FirewallAction) -> Result<(), std::io::Error> {
        let action: NET_FW_ACTION = action.into();
        let ret = unsafe { self.0.put_action(action) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else {
            Ok(())
        }
    }
}

impl std::fmt::Debug for FirewallRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut f = f.debug_struct("FirewallRule");

        if let Ok(name) = self.get_name() {
            f.field("name", &name);
        }

        if let Ok(description) = self.get_description() {
            f.field("description", &description);
        }

        if let Ok(application_name) = self.get_application_name() {
            f.field("application_name", &application_name);
        }

        if let Ok(service_name) = self.get_service_name() {
            f.field("service_name", &service_name);
        }

        if let Ok(protocol) = self.get_protocol() {
            f.field("protocol", &protocol);
        }

        if let Ok(local_ports) = self.get_local_ports() {
            f.field("local_ports", &local_ports);
        }

        if let Ok(remote_ports) = self.get_remote_ports() {
            f.field("remote_ports", &remote_ports);
        }

        if let Ok(local_addresses) = self.get_local_addresses() {
            f.field("local_addresses", &local_addresses);
        }

        if let Ok(remote_addresses) = self.get_remote_addresses() {
            f.field("remote_addresses", &remote_addresses);
        }

        if let Ok(icmp_types_and_codes) = self.get_icmp_types_and_codes() {
            f.field("icmp_types_and_codes", &icmp_types_and_codes);
        }

        if let Ok(direction) = self.get_direction() {
            f.field("direction", &direction);
        }

        if let Ok(interfaces) = self.get_interfaces() {
            f.field("interfaces", &interfaces);
        }

        if let Ok(interface_types) = self.get_interfaces() {
            f.field("interface_types", &interface_types);
        }

        if let Ok(enabled) = self.get_enabled() {
            f.field("enabled", &enabled);
        }

        if let Ok(grouping) = self.get_grouping() {
            f.field("grouping", &grouping);
        }

        if let Ok(profiles) = self.get_profiles() {
            f.field("profiles", &profiles);
        }

        if let Ok(edge_traversal) = self.get_edge_traversal() {
            f.field("edge_traversal", &edge_traversal);
        }

        if let Ok(action) = self.get_action() {
            f.field("action", &action);
        }

        f.finish()
    }
}
