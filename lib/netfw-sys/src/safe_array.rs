use crate::{
    variant::VariantType,
    SafeArrayGetElement,
    SafeArrayGetVartype,
};
/// This is needed by Variant, so this is in sys. Read Variant's docs as to why its in sys.
use bitflags::bitflags;
use com::sys::FAILED;
use std::os::raw::c_void;
use winapi::{
    shared::{
        ntdef::LONG,
        wtypes::VT_EMPTY,
        wtypesbase::USHORT,
    },
    um::{
        oaidl::{
            FADF_AUTO,
            FADF_BSTR,
            FADF_DISPATCH,
            FADF_EMBEDDED,
            FADF_FIXEDSIZE,
            FADF_HAVEIID,
            FADF_HAVEVARTYPE,
            FADF_RECORD,
            FADF_STATIC,
            FADF_UNKNOWN,
            FADF_VARIANT,
            SAFEARRAY,
        },
        oleauto::SafeArrayDestroy,
    },
};

bitflags! {
    pub struct SafeArrayFeatures: USHORT {
        const AUTO = FADF_AUTO as u16;
        const STATIC = FADF_STATIC as u16;
        const EMBEDDED = FADF_EMBEDDED as u16;
        const FIXEDSIZE = FADF_FIXEDSIZE as u16;
        const RECORD = FADF_RECORD as u16;
        const HAVEIID = FADF_HAVEIID as u16;
        const HAVEVARTYPE = FADF_HAVEVARTYPE as u16;
        const BSTR = FADF_BSTR as u16;
        const UNKNOWN = FADF_UNKNOWN as u16;
        const DISPATCH = FADF_DISPATCH as u16;
        const VARIANT = FADF_VARIANT as u16;
    }
}

#[repr(transparent)]
pub struct SafeArray(*mut SAFEARRAY);

impl SafeArray {
    fn get_inner_ref(&self) -> &SAFEARRAY {
        unsafe { &*self.0 }
    }

    /// # Safety
    /// ptr must be a valid SAFEARRAY
    pub unsafe fn new(ptr: *mut SAFEARRAY) -> Self {
        assert!(!ptr.is_null());
        SafeArray(ptr)
    }

    pub fn dimension(&self) -> usize {
        self.get_inner_ref().cDims.into()
    }

    pub fn features(&self) -> SafeArrayFeatures {
        SafeArrayFeatures::from_bits_truncate(self.get_inner_ref().fFeatures)
    }

    pub fn len(&self) -> usize {
        self.get_inner_ref().rgsabound[0].cElements as usize
    }

    pub fn len_bytes(&self) -> usize {
        self.get_inner_ref().cbElements as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn locks(&self) -> usize {
        self.get_inner_ref().cLocks as usize
    }

    pub fn lower_bound(&self) -> usize {
        self.get_inner_ref().rgsabound[0].lLbound as usize
    }

    pub fn get_var_type(&self) -> Result<VariantType, std::io::Error> {
        let mut vt = VT_EMPTY as u16;
        let ret = unsafe { SafeArrayGetVartype(self.0, &mut vt) };

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else {
            Ok(VariantType::from(vt))
        }
    }

    pub fn destroy(self) -> Result<(), (Self, std::io::Error)> {
        let ret = unsafe { SafeArrayDestroy(self.0) };

        if FAILED(ret) {
            return Err((self, std::io::Error::from_raw_os_error(ret)));
        }

        Ok(())
    }

    /// # Safety
    /// T must be the right type.
    pub unsafe fn get<T: Default>(&self, indexes: &[LONG]) -> Result<T, std::io::Error> {
        assert_eq!(
            indexes.len(),
            self.dimension(),
            "The dimension of the array does not match the dimension of the indexes"
        );

        let mut el = Default::default();
        let ret = SafeArrayGetElement(self.0, indexes.as_ptr(), &mut el as *mut T as *mut c_void);

        if FAILED(ret) {
            Err(std::io::Error::from_raw_os_error(ret))
        } else {
            Ok(el)
        }
    }
}

impl Drop for SafeArray {
    fn drop(&mut self) {
        unsafe {
            SafeArrayDestroy(self.0);
        }
    }
}

impl std::fmt::Debug for SafeArray {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let features = self.features();

        let mut f = f.debug_struct("SafeArray");

        f.field("dimension", &self.dimension())
            .field("features", &features)
            .field("len", &self.len())
            .field("len_bytes", &self.len_bytes())
            .field("locks", &self.locks())
            .field("lower_bound", &self.lower_bound());

        if features.contains(SafeArrayFeatures::HAVEVARTYPE) {
            f.field("var_type", &self.get_var_type());
        }

        f.finish()
    }
}
