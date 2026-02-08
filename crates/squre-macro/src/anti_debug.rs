//! Implementation of the `anti_debug!()` proc macro.
//!
//! Now also installs the Nanomite VEH handler for INT3-based
//! branch obfuscation support.

use proc_macro2::TokenStream;
use quote::quote;

/// Generate inline anti-debug check code + process guard + nanomite VEH + tidal memory.
pub fn generate() -> TokenStream {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let tidal_key: u64 = rng.gen();

    // Generate a random 32-byte shared secret for process guard IPC auth
    let secret_bytes: Vec<proc_macro2::TokenStream> = (0..32)
        .map(|_| {
            let b: u8 = rng.gen();
            quote! { #b }
        })
        .collect();

    quote! {
        {
            // ═══ Process Guard: child intercept ═══
            // Must be first! If this binary was re-spawned as sentinel/resolver,
            // enter child loop (never returns — calls std::process::exit).
            if ::squre_runtime::process_guard::maybe_run_as_child() {
                ::std::process::exit(0); // safety net
            }

            // ═══ Anti-debug checks ═══
            let __squre_poison = ::squre_runtime::anti_debug::run_all_checks();
            ::std::hint::black_box(__squre_poison);

            // ═══ Nanomite VEH handler + table loading + activation ═══
            if !::squre_runtime::nanomite::is_installed() {
                unsafe {
                    ::squre_runtime::nanomite::install_handler(
                        ::squre_runtime::nanomite::NanomiteTable::empty()
                    );
                    ::squre_runtime::nanomite::load_table_from_pe_section();
                    ::squre_runtime::nanomite::activate_nanomites();
                }
            }

            // ═══ Process Guard + Tidal Memory ═══
            if !::squre_runtime::tidal::is_active() {
                let __tidal_key: u64 = #tidal_key;

                // Split key via Shamir (k=3, n=3), distribute shares to
                // sentinel/resolver children, recover via Named Pipe IPC.
                let __guard_cfg = ::squre_runtime::process_guard::ProcessGuardConfig {
                    shared_secret: [#(#secret_bytes),*],
                    master_key: __tidal_key,
                };

                let __effective_key = match ::squre_runtime::process_guard::initialize_guard(&__guard_cfg) {
                    Some(k) => k,
                    None => __tidal_key, // fallback if guard spawn fails
                };

                unsafe {
                    ::squre_runtime::tidal::initialize(__effective_key);
                }
            }
        }
    }
}
