#![allow(non_snake_case)]

use std::collections::BTreeMap;

use frost_core::{compute_binding_factor_list, compute_group_commitment, derive_interpolating_value, BindingFactor, BindingFactorList, Ciphersuite};
pub use frost_secp256k1_tr::{
    keys::EvenY, Error, GroupError, Identifier, Secp256K1Group, Secp256K1ScalarField, Secp256K1Sha256TR,
    Signature, SigningPackage, VerifyingKey, Group, Field, GroupCommitment, 
    aggregate, aggregate_with_tweak,
};

use k256::{elliptic_curve::ops::MulByGenerator, ProjectivePoint, Scalar};

pub mod keys {
    pub use frost_secp256k1_tr::keys::*;
}

pub mod round1 {
    pub use frost_core::round1::Nonce;
    pub use frost_secp256k1_tr::round1::*;
}

pub mod round2 {
    use super::*;
    pub use frost_secp256k1_tr::round2::*;

    pub fn sign_with_adaptor_point(
        signing_package: &SigningPackage,
        signer_nonces: &round1::SigningNonces,
        key_package: &keys::KeyPackage,
        adaptor_point: &VerifyingKey,
    ) -> Result<SignatureShare, Error> {
        if signing_package.signing_commitments().len() < *key_package.min_signers() as usize {
            return Err(Error::IncorrectNumberOfCommitments);
        }

        // Validate the signer's commitment is present in the signing package
        let commitment = signing_package
            .signing_commitments()
            .get(&key_package.identifier())
            .ok_or(Error::MissingCommitment)?;

        // Validate if the signer's commitment exists
        if signer_nonces.commitments() != commitment {
            return Err(Error::IncorrectCommitment);
        }

        let (signing_package, signer_nonces, key_package) =
            Secp256K1Sha256TR::pre_sign(signing_package, signer_nonces, key_package)?;

        // Encodes the signing commitment list produced in round one as part of generating [`BindingFactor`], the
        // binding factor.
        let binding_factor_list: BindingFactorList<Secp256K1Sha256TR> =
            compute_binding_factor_list(&signing_package, &key_package.verifying_key(), &[])?;
        let binding_factor: BindingFactor<Secp256K1Sha256TR> = binding_factor_list
            .get(&key_package.identifier())
            .ok_or(frost_secp256k1_tr::Error::UnknownIdentifier)?
            .clone();

        // Compute the group commitment from signing commitments produced in round one.
        let group_commitment = compute_group_commitment(&signing_package, &binding_factor_list)?;

        // adapted group commitment
        let adapted_group_commitment = group_commitment.to_element() + adaptor_point.to_element();

        // Compute Lagrange coefficient.
        let lambda_i =
            derive_interpolating_value(key_package.identifier(), &signing_package)?;

        // Compute the per-message challenge.
        let challenge = Secp256K1Sha256TR::challenge(
            &adapted_group_commitment,
            key_package.verifying_key(),
            signing_package.message(),
        )?;

        // Compute the signature share.
        let signature_share = Secp256K1Sha256TR::compute_signature_share(
            &GroupCommitment::<Secp256K1Sha256TR>::from_element(adapted_group_commitment),
            &signer_nonces,
            binding_factor,
            lambda_i,
            &key_package,
            challenge,
        );

        Ok(signature_share)
    }

    pub fn sign_with_dkg_nonce(
        signing_package: &SigningPackage,
        signer_nonces: &round1::SigningNonces,
        key_package: &keys::KeyPackage,
        group_commitment: &VerifyingKey,
    ) -> Result<SignatureShare, Error> {
        let binding_factor = BindingFactor::deserialize([0u8; 32].to_vec()).unwrap();
        sign_with_group_commitment(signing_package, signer_nonces, key_package, group_commitment, binding_factor, true)
    }

    pub(crate) fn sign_with_group_commitment(
        signing_package: &SigningPackage,
        signer_nonces: &round1::SigningNonces,
        key_package: &keys::KeyPackage,
        group_commitment: &VerifyingKey,
        binding_factor: BindingFactor<Secp256K1Sha256TR>,
        nonces_with_lambda: bool
    ) -> Result<SignatureShare, Error> {
        // Compute Lagrange coefficient.
        let lambda_i = derive_interpolating_value(key_package.identifier(), signing_package)?;

        // Multiply nonces by lambda if nonces_with_lambda is true
        let signer_nonces = if nonces_with_lambda {
            let hiding =  round1::Nonce::from_scalar(lambda_i * signer_nonces.hiding().to_scalar());
            let binding = round1::Nonce::from_scalar(lambda_i * signer_nonces.binding().to_scalar());

            round1::SigningNonces::from_nonces(hiding, binding)
        } else {
            signer_nonces.clone()
        };

        let (signing_package, signer_nonces, key_package) =
            Secp256K1Sha256TR::pre_sign(signing_package, &signer_nonces, key_package)?;

        // Compute the per-message challenge.
        let challenge = <Secp256K1Sha256TR as Ciphersuite>::challenge(
            &group_commitment.to_element(),
            key_package.verifying_key(),
            signing_package.message(),
        )?;

        // Compute the signature share.
        let signature_share = Secp256K1Sha256TR::compute_signature_share(
            &GroupCommitment::<Secp256K1Sha256TR>::from_element(group_commitment.to_element()),
            &signer_nonces,
            binding_factor,
            lambda_i,
            &key_package,
            challenge,
        );

        Ok(signature_share)
    }
}

/// Aggregate the adaptor signature shares with the given adaptor point
pub fn aggregate_with_adaptor_point(
    signing_package: &SigningPackage,
    signature_shares: &BTreeMap<Identifier, round2::SignatureShare>,
    pubkeys: &keys::PublicKeyPackage,
    adaptor_point: &VerifyingKey,
) -> Result<AdaptorSignature, Error> {
    // Check if signing_package.signing_commitments and signature_shares have
    // the same set of identifiers, and if they are all in pubkeys.verifying_shares.
    if signing_package.signing_commitments().len() != signature_shares.len() {
        return Err(Error::UnknownIdentifier);
    }

    if !signing_package.signing_commitments().keys().all(|id| {
        #[cfg(feature = "cheater-detection")]
        return signature_shares.contains_key(id) && pubkeys.verifying_shares().contains_key(id);
        #[cfg(not(feature = "cheater-detection"))]
        return signature_shares.contains_key(id);
    }) {
        return Err(Error::UnknownIdentifier);
    }

    let (signing_package, signature_shares, pubkeys) =
        Secp256K1Sha256TR::pre_aggregate(signing_package, signature_shares, pubkeys)?;

    // Encodes the signing commitment list produced in round one as part of generating [`BindingFactor`], the
    // binding factor.
    let binding_factor_list: BindingFactorList<Secp256K1Sha256TR> =
        compute_binding_factor_list(&signing_package, &pubkeys.verifying_key(), &[])?;
    // Compute the group commitment from signing commitments produced in round one.
    let group_commitment = compute_group_commitment(&signing_package, &binding_factor_list)?;

    // adapted group commitment
    let adapted_group_commitment = group_commitment.to_element() + adaptor_point.to_element();

    // The aggregation of the signature shares by summing them up, resulting in
    // a plain Schnorr signature.
    //
    // Implements [`aggregate`] from the spec.
    //
    // [`aggregate`]: https://datatracker.ietf.org/doc/html/rfc9591#name-signature-share-aggregation
    let mut z = <<Secp256K1Group as Group>::Field>::zero();

    for signature_share in signature_shares.values() {
        z = z + signature_share.share().0;
    }

    let signature = AdaptorSignature(Signature::new(adapted_group_commitment, z));

    // Verify the aggregate signature
    signature.verify_signature(
        signing_package.message(),
        pubkeys.verifying_key(),
        &adaptor_point.to_element(),
    )?;

    Ok(signature)
}

/// Aggregate signature shares with the given group commitment
pub fn aggregate_with_group_commitment(
    signing_package: &SigningPackage,
    signature_shares: &BTreeMap<Identifier, round2::SignatureShare>,
    pubkeys: &keys::PublicKeyPackage,
    group_commitment: &VerifyingKey,
) -> Result<Signature, Error> {
    // Check if signing_package.signing_commitments and signature_shares have
    // the same set of identifiers, and if they are all in pubkeys.verifying_shares.
    if signing_package.signing_commitments().len() != signature_shares.len() {
        return Err(Error::UnknownIdentifier);
    }

    if !signing_package.signing_commitments().keys().all(|id| {
        #[cfg(feature = "cheater-detection")]
        return signature_shares.contains_key(id) && pubkeys.verifying_shares().contains_key(id);
        #[cfg(not(feature = "cheater-detection"))]
        return signature_shares.contains_key(id);
    }) {
        return Err(Error::UnknownIdentifier);
    }

    let (_signing_package, signature_shares, _pubkeys) =
        Secp256K1Sha256TR::pre_aggregate(signing_package, signature_shares, pubkeys)?;

    // The aggregation of the signature shares by summing them up, resulting in
    // a plain Schnorr signature.
    //
    // Implements [`aggregate`] from the spec.
    //
    // [`aggregate`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#section-5.3
    let mut z = <<Secp256K1Group as Group>::Field>::zero();

    for signature_share in signature_shares.values() {
        z = z + signature_share.share().0;
    }

    let signature = Signature::new(group_commitment.to_element(), z);

    Ok(signature)
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AdaptorSignature(pub Signature);

impl AdaptorSignature {
    /// Verify the aggregated adaptor signature
    pub fn verify_signature(&self,
        message: &[u8],
        public_key: &VerifyingKey,
        adaptor_point: &<Secp256K1Group as Group>::Element,
    ) -> Result<(), Error> {
        let adapted_R = self.0.R().to_owned();

        let c = Secp256K1Sha256TR::challenge(&adapted_R, public_key, message)?;

        let vk = public_key.to_element();

        let zB = Secp256K1Group::generator() * self.0.z();
        let cA = vk * c.to_scalar();
        let R = zB - cA;

        let effective_adaptor_point = if !GroupCommitment::<Secp256K1Sha256TR>::from_element(adapted_R).has_even_y()
        {
            adapted_R + R
        } else {
            adapted_R - R
        };

        if effective_adaptor_point == *adaptor_point {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    /// Adapt the adaptor signature with the given adaptor secret.
    pub fn adapt(&self, adaptor_secret: &Scalar) -> Signature {
        let adapted_s = if !GroupCommitment::<Secp256K1Sha256TR>::from_element(*self.0.R()).has_even_y() {
            self.0.z() - adaptor_secret
        } else {
            self.0.z() + adaptor_secret
        };

        Signature::new(*self.0.R(), adapted_s)
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_aaa() {
        // round1::abc()
    }
}
