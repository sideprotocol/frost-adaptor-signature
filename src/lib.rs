
pub use frost_secp256k1_tr::{
    Secp256K1ScalarField, Secp256K1Group, Secp256K1Sha256TR, Identifier,
    Signature, SigningPackage, SigningKey, VerifyingKey,
};
use k256::{elliptic_curve::ops::MulByGenerator, ProjectivePoint, Scalar};

pub mod keys {
    pub use frost_secp256k1_tr::keys::*;
}

pub mod round1 {
    pub use frost_secp256k1_tr::round1::*;
    pub fn sign_with_group_commitment() {

    }
}

pub mod round2 {
    pub use frost_secp256k1_tr::round2::*;
    pub fn aggregate_with_group_commitment() {

    }
}

/// Adapt the adaptor signature with the given adaptor secret.
pub fn adapt(signature: &Signature, adaptor_secret: &Scalar) -> Signature {
    let R = signature.R();
    let s = signature.z();

    let adaptor_point = ProjectivePoint::mul_by_generator(adaptor_secret);
    let adapted_R = R + &adaptor_point;

    let adapted_s = if Secp256K1Group::y_is_odd(&adapted_R) {
        s - adaptor_secret
    } else {
        s + adaptor_secret
    };

    Signature::new(adapted_R, adapted_s)
}


#[cfg(test)]
mod tests {

    #[test]
    fn test_aaa() {
        // round1::abc()
    }
}
