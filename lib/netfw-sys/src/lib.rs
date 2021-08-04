#![allow(non_camel_case_types)]
#![allow(clippy::transmute_ptr_to_ptr)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::from_over_into)]

pub mod safe_array;
pub mod variant;

pub use crate::{
    safe_array::SafeArray,
    variant::Variant,
};
use com::{
    interfaces::IUnknown,
    sys::{
        GUID,
        HRESULT,
    },
};
use std::os::raw::c_void;
use winapi::{
    ctypes::c_long,
    shared::{
        guiddef::REFIID,
        minwindef::{
            UINT,
            WORD,
        },
        ntdef::LONG,
        wtypes::{
            BSTR,
            VARIANT_BOOL,
            VARTYPE,
        },
        wtypesbase::{
            LPOLESTR,
            ULONG,
        },
    },
    um::{
        oaidl::{
            ITypeInfo,
            DISPID,
            DISPPARAMS,
            EXCEPINFO,
            SAFEARRAY,
            VARIANT,
        },
        winnt::LCID,
    },
    ENUM,
};

pub const CLSID_INETFWPOLICY2: GUID = GUID {
    data1: 0xE2B3C97F,
    data2: 0x6AE1,
    data3: 0x41AC,
    data4: 0x817AF6F92166D7DD_u64.to_be_bytes(),
};

pub const CLSID_INETFWRULE: GUID = GUID {
    data1: 0x2C5BC43E,
    data2: 0x3369,
    data3: 0x4C33,
    data4: 0xAB0CBE9469677AF4_u64.to_be_bytes(),
};

ENUM! {
    enum NET_FW_PROFILE_TYPE2 {
        NET_FW_PROFILE2_DOMAIN = 0x1,
        NET_FW_PROFILE2_PRIVATE	= 0x2,
        NET_FW_PROFILE2_PUBLIC = 0x4,
        NET_FW_PROFILE2_ALL	= 0x7fffffff,
    }
}

ENUM! {
    enum NET_FW_ACTION {
        NET_FW_ACTION_BLOCK	= 0,
        NET_FW_ACTION_ALLOW = NET_FW_ACTION_BLOCK + 1,
        NET_FW_ACTION_MAX = NET_FW_ACTION_ALLOW + 1,
    }
}

ENUM! {
    enum NET_FW_RULE_DIRECTION {
        NET_FW_RULE_DIR_IN = 1,
        NET_FW_RULE_DIR_OUT = NET_FW_RULE_DIR_IN + 1,
        NET_FW_RULE_DIR_MAX	= NET_FW_RULE_DIR_OUT + 1,
    }
}

ENUM! {
    enum NET_FW_MODIFY_STATE {
        NET_FW_MODIFY_STATE_OK = 0,
        NET_FW_MODIFY_STATE_GP_OVERRIDE	= NET_FW_MODIFY_STATE_OK + 1,
        NET_FW_MODIFY_STATE_INBOUND_BLOCKED	= NET_FW_MODIFY_STATE_GP_OVERRIDE + 1,
    }
}

com::interfaces! {
    #[uuid("00020400-0000-0000-C000-000000000046")]
    pub unsafe interface IDispatch: IUnknown {
        pub fn get_type_info_count(&self, pctinfo: *mut UINT) -> HRESULT;
        pub fn get_type_info(&self, i_tinfo: UINT, lcid: LCID,  pp_tinfo:  *mut *mut ITypeInfo) -> HRESULT;
        pub fn get_ids_of_names(&self, riid: REFIID, rgsz_names: *mut LPOLESTR, c_names: UINT, lcid:  LCID, rg_disp_id: *mut DISPID) -> HRESULT;
        pub fn invoke(&self, disp_id_member: DISPID, riid: REFIID, lcid: LCID, w_flags: WORD, p_disp_params: *mut DISPPARAMS, p_var_result: *mut VARIANT, p_excep_info: *mut EXCEPINFO, pu_arg_err: *mut UINT) -> HRESULT;
    }

    #[uuid("00020404-0000-0000-C000-000000000046")]
    pub unsafe interface IEnumVARIANT: IUnknown {
        pub fn next(&self, celt: ULONG, rg_var: *mut Variant, p_celt_fetched: *mut ULONG) -> HRESULT;
        pub fn skip(&self, celt: ULONG) -> HRESULT;
        pub fn reset(&self) -> HRESULT;
        pub fn clone(&self, pp_enum: *mut IEnumVARIANT) -> HRESULT;
    }

    #[uuid("AF230D27-BABA-4E42-ACED-F524F22CFCE2")]
    pub unsafe interface INetFwRule: IDispatch {
        pub fn get_name(&self, name: *mut BSTR) -> HRESULT;
        pub fn put_name(&self, name: BSTR) -> HRESULT;
        pub fn get_description(&self, desc: *mut BSTR) -> HRESULT;
        pub fn put_description(&self, desc: BSTR) -> HRESULT;
        pub fn get_application_name(&self, image_file_name: *mut BSTR) -> HRESULT;
        pub fn put_application_name(&self, image_file_name: BSTR) -> HRESULT;
        pub fn get_service_name(&self, service_name: *mut BSTR) -> HRESULT;
        pub fn put_service_name(&self, service_name: BSTR) -> HRESULT;
        pub fn get_protocol(&self, protocol: *mut LONG) -> HRESULT;
        pub fn put_protocol(&self, protocol: LONG) -> HRESULT;
        pub fn get_local_ports(&self, port_numbers: *mut BSTR) -> HRESULT;
        pub fn put_local_ports(&self, port_numbers: BSTR) -> HRESULT;
        pub fn get_remote_ports(&self, port_numbers: *mut BSTR) -> HRESULT;
        pub fn put_remote_ports(&self, port_numbers: BSTR) -> HRESULT;
        pub fn get_local_addresses(&self, local_addrs: *mut BSTR) -> HRESULT;
        pub fn put_local_addresses(&self, local_addrs: BSTR) -> HRESULT;
        pub fn get_remote_addresses(&self, local_addrs: *mut BSTR) -> HRESULT;
        pub fn put_remote_addresses(&self, local_addrs: BSTR) -> HRESULT;
        pub fn get_icmp_types_and_codes(&self, icmp_types_and_codes: *mut BSTR) -> HRESULT;
        pub fn put_icmp_types_and_codes(&self, icmp_types_and_codes: BSTR) -> HRESULT;
        pub fn get_direction(&self, dir: *mut NET_FW_RULE_DIRECTION) -> HRESULT;
        pub fn put_direction(&self, dir: NET_FW_RULE_DIRECTION) -> HRESULT;
        pub fn get_interfaces(&self, interfaces: *mut Variant) -> HRESULT;
        pub fn put_interfaces(&self, interfaces: Variant) -> HRESULT;
        pub fn get_interface_types(&self, interface_types: *mut BSTR) -> HRESULT;
        pub fn put_interface_types(&self, interface_types: BSTR) -> HRESULT;
        pub fn get_enabled(&self, enabled: *mut VARIANT_BOOL) -> HRESULT;
        pub fn put_enabled(&self, enabled: VARIANT_BOOL) -> HRESULT;
        pub fn get_grouping(&self, context: *mut BSTR) -> HRESULT;
        pub fn put_grouping(&self, context: BSTR) -> HRESULT;
        pub fn get_profiles(&self, profile_types_bitmask: *mut c_long) -> HRESULT;
        pub fn put_profiles(&self, profile_types_bitmask: c_long) -> HRESULT;
        pub fn get_edge_traversal(&self, enabled: *mut VARIANT_BOOL) -> HRESULT;
        pub fn put_edge_traversal(&self, enabled: VARIANT_BOOL) -> HRESULT;
        pub fn get_action(&self, action: *mut NET_FW_ACTION) -> HRESULT;
        pub fn put_action(&self, action: NET_FW_ACTION) -> HRESULT;
    }

    #[uuid("9C4C6277-5027-441E-AFAE-CA1F542DA009")]
    pub unsafe interface INetFwRules: IDispatch {
        pub fn get_count(&self, count: *mut c_long) -> HRESULT;
        pub fn add(&self, rule: INetFwRule) -> HRESULT;
        pub fn remove(&self, name: BSTR) -> HRESULT;
        pub fn item(&self, name: BSTR, rule: *mut INetFwRule) -> HRESULT;
        pub fn get_new_enum(&self, new_enum: *mut IUnknown) -> HRESULT;
    }

    #[uuid("8267BBE3-F890-491C-B7B6-2DB1EF0E5D2B")]
    pub unsafe interface INetFwServiceRestriction: IDispatch {
        pub fn restrict_service(&self, service_name: BSTR, app_name: BSTR, restrict_service: VARIANT_BOOL, service_sid_restricted: VARIANT_BOOL) -> HRESULT;
        pub fn service_restricted(&self, service_name: BSTR, app_name: BSTR, service_restricted: *mut VARIANT_BOOL) -> HRESULT;
        pub fn get_rules(&self, rules: *mut INetFwRules) -> HRESULT;
    }

    #[uuid("98325047-C671-4174-8D81-DEFCD3F03186")]
    pub unsafe interface INetFwPolicy2: IDispatch {
        pub fn get_current_profile_types(&self, profile_types_bitmask: *mut c_long) -> HRESULT;
        pub fn get_firewall_enabled(&self, profile_type: NET_FW_PROFILE_TYPE2, enabled: *mut VARIANT_BOOL) -> HRESULT;
        pub fn put_firewall_enabled(&self, profile_type: NET_FW_PROFILE_TYPE2, enabled: VARIANT_BOOL) -> HRESULT;
        pub fn get_excluded_interfaces(&self, profile_type: NET_FW_PROFILE_TYPE2, interfaces: *mut Variant) -> HRESULT;
        pub fn put_excluded_interfaces(&self, profile_type: NET_FW_PROFILE_TYPE2, interfaces: Variant) -> HRESULT;
        pub fn get_block_all_inbound_traffic(&self, profile_type: NET_FW_PROFILE_TYPE2, block: *mut VARIANT_BOOL) -> HRESULT;
        pub fn put_block_all_inbound_traffic(&self, profile_type: NET_FW_PROFILE_TYPE2, block: VARIANT_BOOL) -> HRESULT;
        pub fn get_notifications_disabled(&self, profile_type: NET_FW_PROFILE_TYPE2, disabled: *mut VARIANT_BOOL) -> HRESULT;
        pub fn put_notifications_disabled(&self, profile_type: NET_FW_PROFILE_TYPE2, disabled: VARIANT_BOOL) -> HRESULT;
        pub fn get_unicast_responses_to_multicast_broadcast_disabled(&self, profile_type: NET_FW_PROFILE_TYPE2, disabled: *mut VARIANT_BOOL) -> HRESULT;
        pub fn put_unicast_responses_to_multicast_broadcast_disabled(&self, profile_type: NET_FW_PROFILE_TYPE2, disabled: VARIANT_BOOL) -> HRESULT;
        pub fn get_rules(&self, rules: *mut INetFwRules) -> HRESULT;
        pub fn get_service_restriction(&self, service_restriction: *mut INetFwServiceRestriction) -> HRESULT;
        pub fn enable_rule_group(&self, profile_types_bitmask: c_long, group: BSTR, enable: VARIANT_BOOL) -> HRESULT;
        pub fn is_rule_group_enabled(&self, profile_types_bitmask: c_long, group: BSTR, enable: *mut VARIANT_BOOL) -> HRESULT;
        pub fn restore_local_firewall_defaults(&self) -> HRESULT;
        pub fn get_default_inbound_action(&self, profile_type: NET_FW_PROFILE_TYPE2, action: *mut NET_FW_ACTION) -> HRESULT;
        pub fn put_default_inbound_action(&self, profile_type: NET_FW_PROFILE_TYPE2, action: NET_FW_ACTION) -> HRESULT;
        pub fn get_default_outbound_action(&self, profile_type: NET_FW_PROFILE_TYPE2, action: *mut NET_FW_ACTION) -> HRESULT;
        pub fn put_default_outbound_action(&self, profile_type: NET_FW_PROFILE_TYPE2, action: NET_FW_ACTION) -> HRESULT;
        pub fn get_is_rule_group_currently_enabled(&self, group: BSTR, enabled: *mut VARIANT_BOOL) -> HRESULT;
        pub fn get_local_policy_modify_state(&self, modify_state: *mut NET_FW_MODIFY_STATE) -> HRESULT;
    }
}

extern "system" {
    pub fn SafeArrayGetVartype(psa: *mut SAFEARRAY, pvt: *mut VARTYPE) -> HRESULT;
    pub fn SafeArrayGetElement(
        psa: *mut SAFEARRAY,
        rgIndices: *const LONG,
        pv: *mut c_void,
    ) -> HRESULT;
}
