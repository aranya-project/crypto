#![cfg(not(any(test, doctest)))]
#![no_std]
#![no_main]

extern crate spideroak_crypto;

#[cfg(target_os = "none")] // hack to please rust-analyzer
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

struct BadAllocator;
unsafe impl core::alloc::GlobalAlloc for BadAllocator {
    unsafe fn alloc(&self, _: core::alloc::Layout) -> *mut u8 {
        unimplemented!()
    }
    unsafe fn dealloc(&self, _: *mut u8, _: core::alloc::Layout) {
        unimplemented!()
    }
}

#[global_allocator]
static ALLOCATOR: BadAllocator = BadAllocator;
