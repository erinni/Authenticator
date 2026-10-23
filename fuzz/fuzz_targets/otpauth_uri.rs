#![no_main]

use authenticator_core::OtpAccount;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &str| {
    if let Ok(account) = OtpAccount::from_uri(input) {
        // Ciò che accettiamo deve poter essere esportato e reimportato identico.
        let reparsed = OtpAccount::from_uri(&account.to_uri()).expect("export non reimportabile");
        assert_eq!(reparsed, account);
        let _ = account.totp_at(1_700_000_000);
    }
});
