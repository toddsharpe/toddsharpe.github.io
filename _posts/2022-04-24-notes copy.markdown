---
layout: post
title:  "2022-04-24 - Rust for MetalOS"
date:   2022-04-24
categories: notes
---
Casually browsing how easy it would be to create a standalone rust binary, to run in MetalOS.

Started with no_std attribute, needed panick handler and eh_personality (exception handling).

Compiled with
```
cargo rustc -- -C link-args="/ENTRY:_start /SUBSYSTEM:console"
```

Found some success with
{% highlight rust %}
#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::arch::asm;

/// This function is called on panic.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    DebugPrint("Hello from Rust!");
    ExitProcess();
}

pub fn DebugPrint(string: &str)
{
    unsafe
    {
        asm!
        (
            "mov r10, {0}",
            "mov rax, 600h",
            "syscall",
            "ret",
            in(reg) string.as_ptr(),
        );
    }
}
{% endhighlight %}

Technically does work (but crashes - probably not the right ABI/register restoring):
```
CreateProcess hirust.exe
...
Kernel::KernelThreadInitThunk
KThread
     Id: 8
   Name: hirust.exe[3]
  Start: 0xffff800001010fd0
    Arg: 0x0000000000000000
  State: 1
   User: 0xffff802000036f90
  Rbp: 0x0000000000000000 Rsp: 0xffff800020037fe0 Rip: 0xffff800001010f30 RFlags:0x00000286
UserThread
     Id: 3
  m_teb: 0x00000001400040e0
    ctx: 0xffff802000037050
  Rsp: 0x0000000140107fe0 Rip: 0x00000001800015b0 RFlags:0x00000282
Hello from Rust!ISR: 0xe, Code: 4, RBP: 0x               0, RIP: 0x      1000000003, RSP: 0x       140107ee0
  RAX: 0x               0, RBX: 0x               0, RCX: 0x       140001049, RDX: 0x              10
  CS: 0x2b, SS: 0x23
  CR2: 0x      1000000003
```

Probably not the right way to do this. Better way is to to create bindings off the MetalOS runtime library. Lets take a look at bindgen <https://rust-lang.github.io/rust-bindgen/>

Buildgen
========

Source from: <https://github.com/fitzgen/bindgen-tutorial-bzip2-sys>
Tutorial: <https://fitzgeraldnick.com/2016/12/14/using-libbindgen-in-build-rs.html>

Installed LLVM, set path
```
set LIBCLANG_PATH=C:\Program Files\LLVM\bin
```

Seems bindgen hates my c++ header ```metalos.h``` (<https://stackoverflow.com/questions/52923460/how-to-call-a-c-dynamic-library-from-rust>). Trying to get a minimum header.

Was able to create a metalos crate around a small metalos.h, and import that from a new project:
```
[dependencies.metalos]
path = "..\\metalos_crates\\metalos"
```

However two things
1. It seemed to have added a bunch of dependencies to the new project that the metalos crate needed for bindgen. Ideally this wouldnt happen right?
2. no_std isnt working in the new project, seems the original crate needed it. Interesting.

Without no_std, it doesnt like ```const unsigned char* s``` as function arg. Is degrading to void* right?

Using sources <https://github.com/rust-lang/rust-bindgen/issues/628> and <https://doc.bccnsoft.com/docs/rust-1.36.0-docs-html/embedded-book/interoperability/c-with-rust.html> seems we can set the types directly.

Proof of concept is working!
<https://doc.rust-lang.org/nomicon/ffi.html>

{% highlight rust %}
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#![no_std]

pub mod c_types {
    pub type c_uint = u32;
    pub type c_int = i32;
    pub type c_char = u8;
}

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub fn _print(s: &str)
{
    unsafe
    {
        printf(s.as_ptr());
    }
}
{% endhighlight %}

Using just DebugPrint and printf in metalos.h.

Test app:

{% highlight rust %}
#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn _start() {
    main();
}

fn main() {
    metalos::_print("Hi from Rust!");
}
{% endhighlight %}

Would be cool to get proper println macro working
{% highlight rust %}
#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ({
        $crate::io::_print($crate::format_args_nl!($($arg)*));
    })
}
{% endhighlight %}

References
* <https://os.phil-opp.com/freestanding-rust-binary/>
* <https://github.com/rust-lang/rust-bindgen> - Maybe a way to create bindings from MetalOS RT?
* <https://github.com/rust-lang/rust/tree/master/library/std> - standard library, src/os has os targets, some code has conditional compilation:

```
cfg(any(target_os = "linux", target_os = "android")
```
(<https://github.com/rust-lang/rust/blob/master/library/std/src/io/copy.rs>)