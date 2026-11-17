//! Creating and recovering the root key with Shamir shares (and, with `dev-insecure`, a passphrase).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use common::arena;
use pvlt_core::VaultError;
use pvlt_core::keys::KeyMaterial;
use pvlt_core::seal::{SealMode, UnsealShare, init_shamir, unseal_with_shares};

/// Shares are secrets and cannot be cloned, so tests rebuild them from their text form.
fn pick(shares: &[UnsealShare], idx: &[usize]) -> Vec<UnsealShare> {
    idx.iter()
        .map(|i| UnsealShare::from_text(&shares[*i].to_text()).unwrap())
        .collect()
}

#[test]
fn any_three_of_five_shares_recover_the_root_key() {
    let a = arena();
    let init = init_shamir(&a, 3, 5).unwrap();
    assert_eq!(init.shares.len(), 5);
    assert_eq!(
        init.config.mode,
        SealMode::Shamir {
            threshold: 3,
            shares: 5
        }
    );
    let mut subsets = 0;
    for i in 0..5 {
        for j in i + 1..5 {
            for k in j + 1..5 {
                let root =
                    unseal_with_shares(&a, &init.config, &pick(&init.shares, &[i, j, k])).unwrap();
                assert_eq!(root.expose(), init.root.expose(), "subset {i},{j},{k}");
                assert_eq!(root.id(), init.root.id());
                subsets += 1;
            }
        }
    }
    assert_eq!(subsets, 10);
}

#[test]
fn more_than_the_threshold_also_works() {
    let a = arena();
    let init = init_shamir(&a, 3, 5).unwrap();
    for idx in [&[0, 1, 2, 3][..], &[4, 3, 2, 1, 0][..], &[1, 2, 3, 4][..]] {
        let root = unseal_with_shares(&a, &init.config, &pick(&init.shares, idx)).unwrap();
        assert_eq!(root.expose(), init.root.expose());
    }
}

#[test]
fn fewer_than_the_threshold_recover_nothing() {
    let a = arena();
    let init = init_shamir(&a, 3, 5).unwrap();
    for i in 0..5 {
        for j in i + 1..5 {
            let err =
                unseal_with_shares(&a, &init.config, &pick(&init.shares, &[i, j])).unwrap_err();
            assert_eq!(err, VaultError::Invalid("not enough shares"));
        }
    }
    assert_eq!(
        unseal_with_shares(&a, &init.config, &[]).unwrap_err(),
        VaultError::Invalid("not enough shares")
    );
}

#[test]
fn the_same_share_twice_counts_once() {
    let a = arena();
    let init = init_shamir(&a, 3, 5).unwrap();
    let err = unseal_with_shares(&a, &init.config, &pick(&init.shares, &[0, 0, 1])).unwrap_err();
    assert_eq!(err, VaultError::Invalid("not enough shares"));
    let ok = unseal_with_shares(&a, &init.config, &pick(&init.shares, &[0, 0, 1, 2])).unwrap();
    assert_eq!(ok.expose(), init.root.expose());
}

#[test]
fn threshold_limits() {
    let a = arena();
    assert_eq!(
        init_shamir(&a, 1, 3).unwrap_err(),
        VaultError::Invalid("threshold must be at least 2")
    );
    assert_eq!(
        init_shamir(&a, 0, 3).unwrap_err(),
        VaultError::Invalid("threshold must be at least 2")
    );
    assert_eq!(
        init_shamir(&a, 4, 3).unwrap_err(),
        VaultError::Invalid("fewer shares than the threshold")
    );

    let two = init_shamir(&a, 2, 2).unwrap();
    let r = unseal_with_shares(&a, &two.config, &pick(&two.shares, &[1, 0])).unwrap();
    assert_eq!(r.expose(), two.root.expose());

    let wide = init_shamir(&a, 2, 255).unwrap();
    assert_eq!(wide.shares.len(), 255);
    let r = unseal_with_shares(&a, &wide.config, &pick(&wide.shares, &[17, 254])).unwrap();
    assert_eq!(r.expose(), wide.root.expose());

    let all = init_shamir(&a, 255, 255).unwrap();
    let every: Vec<usize> = (0..255).collect();
    let r = unseal_with_shares(&a, &all.config, &pick(&all.shares, &every)).unwrap();
    assert_eq!(r.expose(), all.root.expose());
}

#[test]
fn share_numbers_are_distinct_and_cover_one_to_n() {
    let a = arena();
    let init = init_shamir(&a, 3, 5).unwrap();
    let mut numbers: Vec<u8> = init
        .shares
        .iter()
        .map(|s| s.info().unwrap().index)
        .collect();
    numbers.sort_unstable();
    assert_eq!(numbers, vec![1, 2, 3, 4, 5]);
    let info = init.shares[0].info().unwrap();
    assert_eq!((info.threshold, &info.root_key_id), (3, init.root.id()));
}

#[test]
fn share_text_form() {
    let a = arena();
    let init = init_shamir(&a, 3, 5).unwrap();
    let text = init.shares[0].to_text();
    assert!(text.starts_with("pvlt-share-v1:"));
    assert_eq!(text.len(), "pvlt-share-v1:".len() + 55 * 2);
    assert!(
        text["pvlt-share-v1:".len()..]
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    let back = UnsealShare::from_text(&format!("  {}\n", *text)).unwrap();
    assert_eq!(
        back.info().unwrap(),
        init.shares[0].info().unwrap(),
        "surrounding whitespace is ignored"
    );
}

#[test]
fn a_single_mistyped_character_is_always_caught() {
    let a = arena();
    let init = init_shamir(&a, 3, 5).unwrap();
    let text = init.shares[0].to_text().to_string();
    let start = "pvlt-share-v1:".len();
    for pos in start..text.len() {
        let mut chars: Vec<char> = text.chars().collect();
        chars[pos] = if chars[pos] == '0' { '1' } else { '0' };
        let typo: String = chars.into_iter().collect();
        let share = UnsealShare::from_text(&typo).unwrap();
        let err = share.info().unwrap_err();
        assert!(
            matches!(err, VaultError::Invalid(m) if m.contains("checksum")),
            "position {pos}: {err:?}"
        );
        let mut with_typo = pick(&init.shares, &[1, 2]);
        with_typo.push(share);
        assert!(
            unseal_with_shares(&a, &init.config, &with_typo).is_err(),
            "position {pos}"
        );
    }
}

#[test]
fn malformed_text_is_rejected_with_a_reason() {
    let a = arena();
    let init = init_shamir(&a, 3, 5).unwrap();
    let good = init.shares[0].to_text().to_string();
    let hex_part = &good["pvlt-share-v1:".len()..];
    let cases = [
        ("", "not a pvlt share"),
        ("hello", "not a pvlt share"),
        (hex_part, "not a pvlt share"),
        ("pvlt-share-v2:00", "not a pvlt share"),
        ("pvlt-share-v1:zz", "share is not valid hex"),
        ("pvlt-share-v1:abc", "share is not valid hex"),
        ("pvlt-share-v1:00", "share has the wrong length"),
    ];
    for (text, why) in cases {
        assert_eq!(
            UnsealShare::from_text(text).unwrap_err(),
            VaultError::Invalid(why),
            "{text:?}"
        );
    }
    let longer = format!("{good}00");
    assert_eq!(
        UnsealShare::from_text(&longer).unwrap_err(),
        VaultError::Invalid("share has the wrong length")
    );
}

#[test]
fn shares_from_another_vault_are_refused_by_name() {
    let a = arena();
    let one = init_shamir(&a, 3, 5).unwrap();
    let two = init_shamir(&a, 3, 5).unwrap();
    assert_ne!(one.root.id(), two.root.id());
    let err = unseal_with_shares(&a, &one.config, &pick(&two.shares, &[0, 1, 2])).unwrap_err();
    assert_eq!(
        err,
        VaultError::Invalid("share is for a different root key")
    );
    let mixed = [
        pick(&one.shares, &[0]).remove(0),
        pick(&two.shares, &[1]).remove(0),
        pick(&one.shares, &[2]).remove(0),
    ];
    assert_eq!(
        unseal_with_shares(&a, &one.config, &mixed).unwrap_err(),
        VaultError::Invalid("share is for a different root key")
    );
}

#[test]
fn a_damaged_wrapped_root_does_not_open_even_with_all_shares() {
    let a = arena();
    let init = init_shamir(&a, 3, 5).unwrap();
    let mut config = init.config.clone();
    config.root.wrapped[70] ^= 1;
    assert!(unseal_with_shares(&a, &config, &pick(&init.shares, &[0, 1, 2])).is_err());
}

#[test]
fn two_initialisations_never_share_anything() {
    let a = arena();
    let one = init_shamir(&a, 3, 5).unwrap();
    let two = init_shamir(&a, 3, 5).unwrap();
    assert_ne!(one.root.expose(), two.root.expose());
    assert_ne!(one.config.root.wrapped, two.config.root.wrapped);
    assert_ne!(*one.shares[0].to_text(), *two.shares[0].to_text());
}

#[test]
fn a_share_alone_shows_nothing_in_debug() {
    let a = arena();
    let init = init_shamir(&a, 3, 5).unwrap();
    let text = init.shares[0].to_text();
    let shown = format!("{:?} {:?}", init.shares[0], init);
    assert_eq!(format!("{:?}", init.shares[0]), "UnsealShare(..)");
    assert!(!shown.contains(&text["pvlt-share-v1:".len()..]));
}

#[test]
fn the_unsealed_root_is_in_the_arena() {
    let a = arena();
    let before = a.slots_in_use();
    let init = init_shamir(&a, 3, 5).unwrap();
    assert_eq!(
        a.slots_in_use(),
        before + 1,
        "only the root key is kept; the unseal key is not"
    );
    drop(init);
    assert_eq!(a.slots_in_use(), before);
}

#[cfg(feature = "dev-insecure")]
mod passphrase {
    use super::*;
    use pvlt_core::seal::{PassphraseParams, init_passphrase, unseal_with_passphrase};

    fn cheap() -> PassphraseParams {
        // The real defaults are 64 MiB; tests use the cheapest parameters Argon2 accepts.
        PassphraseParams {
            m_kib: 8,
            t_cost: 1,
            p_cost: 1,
            salt: [7; 16],
        }
    }

    #[test]
    fn round_trips_and_a_wrong_passphrase_fails() {
        let a = arena();
        let init = init_passphrase(&a, b"correct horse battery", cheap()).unwrap();
        assert!(init.shares.is_empty());
        let root = unseal_with_passphrase(&a, &init.config, b"correct horse battery").unwrap();
        assert_eq!(root.expose(), init.root.expose());
        assert_eq!(
            unseal_with_passphrase(&a, &init.config, b"correct horse batterz").unwrap_err(),
            VaultError::OpenFailed
        );
    }

    #[test]
    fn short_passphrases_are_refused_and_modes_do_not_mix() {
        let a = arena();
        assert_eq!(
            init_passphrase(&a, b"short", cheap()).unwrap_err(),
            VaultError::Invalid("passphrase must be at least 12 bytes")
        );
        let pass = init_passphrase(&a, b"correct horse battery", cheap()).unwrap();
        assert!(unseal_with_shares(&a, &pass.config, &[]).is_err());
        let shamir = init_shamir(&a, 2, 3).unwrap();
        assert_eq!(
            unseal_with_passphrase(&a, &shamir.config, b"correct horse battery").unwrap_err(),
            VaultError::Invalid("this vault is not sealed with a passphrase")
        );
    }

    #[test]
    fn the_salt_changes_the_key() {
        let a = arena();
        let init = init_passphrase(&a, b"correct horse battery", cheap()).unwrap();
        let mut other = init.config.clone();
        if let SealMode::Passphrase(p) = &mut other.mode {
            p.salt = [8; 16];
        }
        assert_eq!(
            unseal_with_passphrase(&a, &other, b"correct horse battery").unwrap_err(),
            VaultError::OpenFailed
        );
    }

    #[test]
    fn recommended_parameters_are_the_rfc_9106_second_choice() {
        let p = PassphraseParams::recommended().unwrap();
        assert_eq!((p.m_kib, p.t_cost, p.p_cost), (65_536, 3, 4));
        assert_ne!(p.salt, PassphraseParams::recommended().unwrap().salt);
    }
}
