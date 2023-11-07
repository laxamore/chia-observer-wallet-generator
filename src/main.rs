mod derive_synthetic;
mod curry_tree_hash;

use bech32::ToBase32;
use hex_literal::hex;
use chia_bls::{G1Element, DerivableKey};
use clvm_utils::tree_hash_atom;

use crate::curry_tree_hash::curry_tree_hash;

static DEFAULT_HIDDEN_PUZZLE_HASH: [u8; 32] = hex!("711d6c4e32c92e53179b199484cf8c897542bc57f2b22582799f9d657eec4699");
static STANDARD_PUZZLE_HASH: [u8; 32] = hex!("e9aaa49f45bad5c889b86ee3341550c155cfdd10c3a6757de618d20612fffd52");

fn main() {
    // Public Key String Hex to array of bytes
    let pk_bytes: [u8; 48] = hex!("ae838c89fe44942603502f3e8a894d1a667a5478c432dc81556178c6b50b8d80d73783e820756972c6665605d79db3d8");
    let g1  = G1Element::from_bytes(&pk_bytes).unwrap();

    // Derive Unhardened
    let g1 = DerivableKey::derive_unhardened(&g1, 12381);
    let g1 = DerivableKey::derive_unhardened(&g1, 8444);
    let g1 = DerivableKey::derive_unhardened(&g1, 2);

    for i in 0..100 {
        let g1 = DerivableKey::derive_unhardened(&g1, i);

        // Derive Synthetic
        let synthetic_key = derive_synthetic::DeriveSynthetic::derive_synthetic(&g1, &DEFAULT_HIDDEN_PUZZLE_HASH);
        // Get Public Key Tree Hash
        let pk_tree_hash = tree_hash_atom(&synthetic_key.to_bytes());
        // Get Puzzle Hash
        let puzzle_hash = curry_tree_hash(STANDARD_PUZZLE_HASH, &[pk_tree_hash]);

        // Get Wallet Address
        let wallet_address = bech32::encode("xch", puzzle_hash.to_vec().to_base32(), bech32::Variant::Bech32m).unwrap();
        println!("wallet_address: {}", wallet_address);
    }
}