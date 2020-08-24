use crate::{
    FirewallAction,
    FirewallProfile,
    FirewallRules,
};
use com::{
    runtime::create_instance,
    sys::FAILED,
};
use netfw_sys::{
    INetFwPolicy2,
    Variant,
    CLSID_INETFWPOLICY2,
    NET_FW_ACTION,
    NET_FW_PROFILE_TYPE2,
};
use std::{
    convert::TryFrom,
    mem::MaybeUninit,
};
use winapi::shared::wtypes::{
    VARIANT_FALSE,
    VARIANT_TRUE,
};

#[repr(transparent)]
pub struct FirewallPolicy(INetFwPolicy2);

impl FirewallPolicy {
    pub fn new() -> Result<Self, std::io::Error> {
        create_instance::<INetFwPolicy2>(&CLSID_INETFWPOLICY2)
            .map(FirewallPolicy)
            .map_err(std::io::Error::from_raw_os_error)
    }

    pub fn current_profile_types(&self) -> Result<FirewallProfile, std::io::Error> {
        let mut mask = 0;
        let ret = unsafe { self.0.get_current_profile_types(&mut mask) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else {
            Ok(FirewallProfile::from_bits_truncate(mask as u32))
        }
    }

    pub fn get_firewall_enabled(&self, profile: FirewallProfile) -> Result<bool, std::io::Error> {
        let mut enabled = VARIANT_FALSE;
        let profile: NET_FW_PROFILE_TYPE2 = profile.into();
        let ret = unsafe { self.0.get_firewall_enabled(profile, &mut enabled) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else {
            Ok(enabled == VARIANT_TRUE)
        }
    }

    pub fn get_excluded_interfaces(
        &self,
        profile: FirewallProfile,
    ) -> Result<Variant, std::io::Error> {
        let profile: NET_FW_PROFILE_TYPE2 = profile.into();
        let mut variant = Variant::new();

        let ret = unsafe { self.0.get_excluded_interfaces(profile, &mut variant) };
        if FAILED(ret) {
            return Err(std::io::Error::from_raw_os_error(ret));
        }

        Ok(variant)
    }

    pub fn get_block_all_inbound_traffic(
        &self,
        profile: FirewallProfile,
    ) -> Result<bool, std::io::Error> {
        let profile: NET_FW_PROFILE_TYPE2 = profile.into();
        let mut block = VARIANT_FALSE;
        let ret = unsafe { self.0.get_block_all_inbound_traffic(profile, &mut block) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else {
            Ok(block == VARIANT_TRUE)
        }
    }

    pub fn get_notifications_disabled(
        &self,
        profile: FirewallProfile,
    ) -> Result<bool, std::io::Error> {
        let profile: NET_FW_PROFILE_TYPE2 = profile.into();
        let mut disabled = VARIANT_FALSE;
        let ret = unsafe { self.0.get_notifications_disabled(profile, &mut disabled) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else {
            Ok(disabled == VARIANT_TRUE)
        }
    }

    pub fn get_unicast_responses_to_multicast_broadcast_disabled(
        &self,
        profile: FirewallProfile,
    ) -> Result<bool, std::io::Error> {
        let profile: NET_FW_PROFILE_TYPE2 = profile.into();
        let mut disabled = VARIANT_FALSE;
        let ret = unsafe {
            self.0
                .get_unicast_responses_to_multicast_broadcast_disabled(profile, &mut disabled)
        };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else {
            Ok(disabled == VARIANT_TRUE)
        }
    }

    pub fn get_rules(&self) -> Result<FirewallRules, std::io::Error> {
        let mut rules = MaybeUninit::zeroed(); // NULL
        let ret = unsafe { self.0.get_rules(rules.as_mut_ptr()) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else {
            Ok(unsafe { FirewallRules(rules.assume_init()) })
        }
    }

    pub fn get_default_inbound_action(
        &self,
        profile: FirewallProfile,
    ) -> Result<FirewallAction, std::io::Error> {
        let profile: NET_FW_PROFILE_TYPE2 = profile.into();
        let mut action: NET_FW_ACTION = FirewallAction::Block.into();
        let ret = unsafe { self.0.get_default_inbound_action(profile, &mut action) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else {
            Ok(FirewallAction::try_from(action).expect("Valid NET_FW_ACTION"))
        }
    }

    pub fn get_default_outbound_action(
        &self,
        profile: FirewallProfile,
    ) -> Result<FirewallAction, std::io::Error> {
        let profile: NET_FW_PROFILE_TYPE2 = profile.into();
        let mut action: NET_FW_ACTION = FirewallAction::Block.into();
        let ret = unsafe { self.0.get_default_outbound_action(profile, &mut action) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else {
            Ok(FirewallAction::try_from(action).expect("Valid NET_FW_ACTION"))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use com::runtime::init_runtime;

    fn display_firewall_info(
        policy: &FirewallPolicy,
        profile: FirewallProfile,
    ) -> Result<(), std::io::Error> {
        println!("******************************************");

        if let Ok(enabled) = policy.get_firewall_enabled(profile) {
            println!(
                "Firewall is {}",
                if enabled { "enabled" } else { "disabled" }
            );
        }

        if let Ok(enabled) = policy.get_block_all_inbound_traffic(profile) {
            println!(
                "Block all inbound traffic is {}",
                if enabled { "enabled" } else { "disabled" }
            );
        }

        if let Ok(enabled) = policy.get_notifications_disabled(profile) {
            println!(
                "Notifications are {}",
                if enabled { "disabled" } else { "enabled" }
            );
        }

        if let Ok(enabled) = policy.get_unicast_responses_to_multicast_broadcast_disabled(profile) {
            println!(
                "UnicastResponsesToMulticastBroadcast is {}",
                if enabled { "disabled" } else { "enabled" }
            );
        }

        if let Ok(action) = policy.get_default_inbound_action(profile) {
            println!(
                "Default inbound action is {}",
                if action != FirewallAction::Block {
                    "Allow"
                } else {
                    "Block"
                }
            );
        }

        if let Ok(action) = policy.get_default_outbound_action(profile) {
            println!(
                "Default outbound action is {}",
                if action != FirewallAction::Block {
                    "Allow"
                } else {
                    "Block"
                }
            );
        }

        println!();
        Ok(())
    }

    #[test]
    fn it_works() {
        init_runtime().unwrap();
        let firewall_policy = FirewallPolicy::new().unwrap();

        println!("Settings for the firewall domain profile:");
        display_firewall_info(&firewall_policy, FirewallProfile::DOMAIN).unwrap();

        println!("Settings for the firewall private profile:");
        display_firewall_info(&firewall_policy, FirewallProfile::PRIVATE).unwrap();

        println!("Settings for the firewall public profile:");
        display_firewall_info(&firewall_policy, FirewallProfile::PUBLIC).unwrap();
    }
}
