pub(crate) mod soft;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) mod sse2;
