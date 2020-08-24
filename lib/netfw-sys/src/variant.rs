/// This is included as part of the sys module since it also acts as a safe abi wrapper and is used as a way to cross VARIANTs across the com abi boundary.
/// To avoid this, I would have to create a wrapper specifically for crossing the ABI boundary,
/// and then wrap that with this higher level abstraction which seems pointlessly complicated when this def could just be moved into the sys crate.
use crate::IDispatch;
use crate::SafeArray;
use com::{
    sys::FAILED,
    AbiTransferable,
};
use std::mem::{
    ManuallyDrop,
    MaybeUninit,
};
use winapi::{
    shared::wtypes::{
        BSTR,
        VARENUM,
        VARTYPE,
        VT_ARRAY,
        VT_BSTR,
        VT_DISPATCH,
        VT_EMPTY,
        VT_NULL,
        VT_VARIANT,
    },
    um::{
        oaidl::VARIANT,
        oleauto::{
            VariantClear,
            VariantInit,
        },
    },
};

const VT_VARIANT_ARRAY: VARENUM = VT_ARRAY | VT_VARIANT;

// TODO: Consider making bitfield
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum VariantType {
    Empty,
    Null,

    BStr,
    Dispatch,

    Variant,

    VariantArray,

    Unknown(VARTYPE),
}

impl VariantType {
    pub fn is_array(self) -> bool {
        let vt: VARTYPE = self.into();

        u32::from(vt) & VT_ARRAY != 0
    }

    pub fn array_type(self) -> Option<VariantType> {
        let vt: VARTYPE = self.into();

        if u32::from(vt) & VT_ARRAY == 0 {
            return None;
        }

        let vt = vt ^ VT_ARRAY as u16;

        Some(vt.into())
    }
}

impl Into<VARTYPE> for VariantType {
    fn into(self) -> VARTYPE {
        match self {
            VariantType::Empty => VT_EMPTY as u16,
            VariantType::Null => VT_NULL as u16,
            VariantType::BStr => VT_BSTR as u16,
            VariantType::Dispatch => VT_DISPATCH as u16,
            VariantType::Variant => VT_VARIANT as u16,
            VariantType::VariantArray => VT_VARIANT_ARRAY as u16,
            VariantType::Unknown(t) => t,
        }
    }
}

impl From<VARTYPE> for VariantType {
    fn from(vt: VARTYPE) -> Self {
        match u32::from(vt) {
            VT_EMPTY => VariantType::Empty,
            VT_NULL => VariantType::Null,
            VT_BSTR => VariantType::BStr,
            VT_DISPATCH => VariantType::Dispatch,
            VT_VARIANT => VariantType::Variant,
            VT_VARIANT_ARRAY => VariantType::VariantArray,
            _ => VariantType::Unknown(vt),
        }
    }
}

#[repr(transparent)]
pub struct Variant(VARIANT);

impl Variant {
    /// Sets VT field. Probably makes all interaction defined?
    pub fn new() -> Self {
        let mut variant = MaybeUninit::zeroed();
        unsafe {
            VariantInit(variant.as_mut_ptr());
            Variant(variant.assume_init())
        }
    }

    /// # Safety
    /// variant must be initalized
    pub unsafe fn from_winapi_variant(variant: VARIANT) -> Self {
        Variant(variant)
    }

    pub fn as_mut_ptr(&mut self) -> *mut VARIANT {
        &mut self.0
    }

    pub fn variant_type(&self) -> VariantType {
        unsafe { self.0.n1.n2().vt.into() }
    }

    pub fn as_bstr(&self) -> Option<BSTR> {
        match self.variant_type() {
            VariantType::BStr => Some(unsafe { *self.0.n1.n2().n3.bstrVal() }),
            _ => None,
        }
    }

    pub fn as_dispatch(&self) -> Option<&IDispatch> {
        match self.variant_type() {
            VariantType::Dispatch => unsafe { std::mem::transmute(self.0.n1.n2().n3.pdispVal()) },
            _ => None,
        }
    }

    /// You should not manually drop this value as the Variant still retains ownership over it.
    /// This leads to a double free.
    pub fn as_array(&self) -> Option<ManuallyDrop<SafeArray>> {
        if self.variant_type().is_array() {
            Some(ManuallyDrop::new(unsafe {
                SafeArray::new(*self.0.n1.n2().n3.parray())
            }))
        } else {
            None
        }
    }

    pub fn clear(mut self) -> Result<(), (std::io::Error, Self)> {
        let ret = unsafe { VariantClear(self.as_mut_ptr()) };
        if FAILED(ret) {
            return Err((std::io::Error::from_raw_os_error(ret), self));
        }

        Ok(())
    }
}

impl std::fmt::Debug for Variant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let variant_type = self.variant_type();

        // Consider making this an enum disp
        f.debug_struct("Variant")
            .field("variant_type", &variant_type)
            .field("bstr", &self.as_bstr())
            .field("dispatch", &self.as_dispatch())
            .finish()
    }
}

impl Default for Variant {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Variant {
    fn drop(&mut self) {
        unsafe {
            VariantClear(self.as_mut_ptr());
        }
    }
}

unsafe impl AbiTransferable for Variant {
    type Abi = VARIANT;

    fn get_abi(&self) -> Self::Abi {
        self.0
    }

    fn set_abi(&mut self) -> *mut Self::Abi {
        &mut self.0
    }
}
