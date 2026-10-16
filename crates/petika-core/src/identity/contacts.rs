//! Local trust pins. A valid directory self-signature never implies user verification.
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{MAX_COUNTER, PublicIdentity, UnlockedIdentity, valid_id};
use crate::{Error, Result};

pub const MAX_VERIFIED_CONTACTS: usize = 128;

/// Stored only inside the encrypted private bundle. No mutation setters are exposed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct ContactPin {
    user_id: String,
    identity_version: u64,
    fingerprint: String,
    suspended: bool,
    revision: u64,
}

impl ContactPin {
    pub fn user_id(&self) -> &str {
        &self.user_id
    }
    pub fn identity_version(&self) -> u64 {
        self.identity_version
    }
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
    pub fn suspended(&self) -> bool {
        self.suspended
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }

    fn matches(&self, candidate: &PublicIdentity) -> bool {
        self.identity_version == candidate.identity_version
            && self.fingerprint == candidate.fingerprint
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContactStatus {
    Unverified,
    Verified,
    Changed,
    Rollback,
    /// A previous key change/rollback was observed; explicit re-verification is required
    /// even if the directory has gone back to serving the pinned identity.
    Suspended,
}

pub(super) fn validate_pins(pins: &[ContactPin], owner: &PublicIdentity) -> Result<()> {
    if pins.len() > MAX_VERIFIED_CONTACTS {
        return Err(Error::ContactLimit);
    }
    let mut previous: Option<&str> = None;
    for pin in pins {
        if !valid_id(&pin.user_id)
            || pin.user_id == owner.user_id
            || !valid_id(&pin.fingerprint)
            || !(1..=MAX_COUNTER).contains(&pin.identity_version)
            || !(1..=MAX_COUNTER).contains(&pin.revision)
            || previous.is_some_and(|id| id >= pin.user_id.as_str())
        {
            return Err(Error::Format);
        }
        previous = Some(&pin.user_id);
    }
    Ok(())
}

impl UnlockedIdentity {
    /// Pins are scoped to this identity's deployment; they are not a server directory.
    pub fn contact_pin(&self, user_id: &str) -> Option<&ContactPin> {
        self.contacts
            .binary_search_by(|pin| pin.user_id.as_str().cmp(user_id))
            .ok()
            .map(|index| &self.contacts[index])
    }

    fn validate_contact(&self, expected_user_id: &str, candidate: &PublicIdentity) -> Result<()> {
        if !valid_id(expected_user_id)
            || expected_user_id == self.public.user_id
            || candidate.user_id != expected_user_id
            || candidate.deployment_id != self.public.deployment_id
        {
            return Err(Error::Authentication);
        }
        candidate.validate()
    }

    /// Observe a signed record for the requested user. Valid changed/older records
    /// suspend an existing pin without replacing it. Persist after a suspension.
    pub fn observe_contact(
        &mut self,
        expected_user_id: &str,
        candidate: &PublicIdentity,
    ) -> Result<ContactStatus> {
        self.validate_contact(expected_user_id, candidate)?;
        let Ok(index) = self
            .contacts
            .binary_search_by(|pin| pin.user_id.as_str().cmp(expected_user_id))
        else {
            return Ok(ContactStatus::Unverified);
        };
        let pin = &mut self.contacts[index];
        let status = if candidate.identity_version < pin.identity_version {
            ContactStatus::Rollback
        } else if !pin.matches(candidate) {
            ContactStatus::Changed
        } else if pin.suspended {
            ContactStatus::Suspended
        } else {
            ContactStatus::Verified
        };
        if matches!(status, ContactStatus::Changed | ContactStatus::Rollback) && !pin.suspended {
            // Exhaustion must still suspend access; a full pin cannot be reverified.
            pin.suspended = true;
            pin.revision = pin.revision.saturating_add(1).min(MAX_COUNTER);
        }
        Ok(status)
    }

    /// Gate for future package consumers/producers. Does not grant server membership.
    /// Errors caused by observed key changes also suspend the pin in memory.
    pub fn require_verified_contact(
        &mut self,
        expected_user_id: &str,
        candidate: &PublicIdentity,
    ) -> Result<()> {
        match self.observe_contact(expected_user_id, candidate)? {
            ContactStatus::Verified => Ok(()),
            ContactStatus::Unverified => Err(Error::UnverifiedContact),
            ContactStatus::Changed | ContactStatus::Suspended => Err(Error::ContactKeyChanged),
            ContactStatus::Rollback => Err(Error::ContactRollback),
        }
    }

    /// The caller must obtain `confirmed_fingerprint` through an independent trusted
    /// channel. Never pass the directory's value as an automatic confirmation.
    /// `expected_pin` is the exact local pin shown when confirmation began (None for a
    /// new contact); compare-and-swap prevents stale verification from replacing it.
    pub fn verify_contact(
        &mut self,
        expected_user_id: &str,
        candidate: &PublicIdentity,
        confirmed_fingerprint: &str,
        expected_pin: Option<&ContactPin>,
    ) -> Result<()> {
        self.validate_contact(expected_user_id, candidate)?;
        if !valid_id(confirmed_fingerprint) || confirmed_fingerprint != candidate.fingerprint {
            return Err(Error::Authentication);
        }
        let position = self
            .contacts
            .binary_search_by(|pin| pin.user_id.as_str().cmp(expected_user_id));
        let current = position.ok().map(|index| &self.contacts[index]);
        if current != expected_pin {
            return Err(Error::ContactConflict);
        }
        let revision = if let Some(pin) = current {
            if candidate.identity_version < pin.identity_version {
                return Err(Error::ContactRollback);
            }
            if candidate.identity_version == pin.identity_version && !pin.matches(candidate) {
                return Err(Error::ContactKeyChanged);
            }
            if pin.matches(candidate) && !pin.suspended {
                return Ok(());
            }
            pin.revision
                .checked_add(1)
                .filter(|revision| *revision <= MAX_COUNTER)
                .ok_or(Error::ContactConflict)?
        } else {
            if self.contacts.len() == MAX_VERIFIED_CONTACTS {
                return Err(Error::ContactLimit);
            }
            1
        };
        let pin = ContactPin {
            user_id: expected_user_id.into(),
            identity_version: candidate.identity_version,
            fingerprint: confirmed_fingerprint.into(),
            suspended: false,
            revision,
        };
        match position {
            Ok(index) => self.contacts[index] = pin,
            Err(index) => self.contacts.insert(index, pin),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_pin_validation_rejects_ambiguous_or_invalid_state() {
        let owner = UnlockedIdentity::generate(&"a".repeat(64), &"b".repeat(64), 1).unwrap();
        let valid = ContactPin {
            user_id: "c".repeat(64),
            identity_version: 1,
            fingerprint: "d".repeat(64),
            suspended: false,
            revision: 1,
        };
        validate_pins(std::slice::from_ref(&valid), owner.public_identity()).unwrap();
        assert!(validate_pins(&[valid.clone(), valid.clone()], owner.public_identity()).is_err());
        assert!(matches!(
            validate_pins(
                &vec![valid.clone(); MAX_VERIFIED_CONTACTS + 1],
                owner.public_identity()
            ),
            Err(Error::ContactLimit)
        ));
        for field in ["user_id", "identity_version", "fingerprint", "revision"] {
            let mut pin = valid.clone();
            match field {
                "user_id" => pin.user_id = owner.public_identity().user_id.clone(),
                "identity_version" => pin.identity_version = 0,
                "fingerprint" => pin.fingerprint = "invalid".into(),
                "revision" => pin.revision = 0,
                _ => unreachable!(),
            }
            assert!(
                matches!(
                    validate_pins(&[pin], owner.public_identity()),
                    Err(Error::Format)
                ),
                "{field}"
            );
        }
        let mut earlier = valid.clone();
        earlier.user_id = "a".repeat(64);
        assert!(matches!(
            validate_pins(&[valid, earlier], owner.public_identity()),
            Err(Error::Format)
        ));
    }
}
