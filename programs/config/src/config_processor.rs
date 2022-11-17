//! Config program

use {
    crate::ConfigKeys,
    bincode::deserialize,
    solana_program_runtime::{ic_msg, invoke_context::InvokeContext},
    solana_sdk::{
        account::{ReadableAccount, WritableAccount},
        feature_set,
        instruction::InstructionError,
        keyed_account::keyed_account_at_index,
        program_utils::limited_deserialize,
        pubkey::Pubkey,
    },
    std::collections::BTreeSet,
};

pub fn process_instruction(
    first_instruction_account: usize,
    data: &[u8],
    invoke_context: &mut InvokeContext,
) -> Result<(), InstructionError> {
    let keyed_accounts = invoke_context.get_keyed_accounts()?;

    let key_list: ConfigKeys = limited_deserialize(data)?;
    let config_keyed_account =
        &mut keyed_account_at_index(keyed_accounts, first_instruction_account)?;
    let current_data: ConfigKeys = {
        let config_account = config_keyed_account.try_account_ref_mut()?;
        if config_account.owner() != &crate::id() {
            return Err(InstructionError::InvalidAccountOwner);
        }

        deserialize(config_account.data()).map_err(|err| {
            ic_msg!(
                invoke_context,
                "Unable to deserialize config account: {}",
                err
            );
            InstructionError::InvalidAccountData
        })?
    };
    let current_signer_keys: Vec<Pubkey> = current_data
        .keys
        .iter()
        .filter(|(_, is_signer)| *is_signer)
        .map(|(pubkey, _)| *pubkey)
        .collect();

    if current_signer_keys.is_empty() {
        // Config account keypair must be a signer on account initialization,
        // or when no signers specified in Config data
        if config_keyed_account.signer_key().is_none() {
            return Err(InstructionError::MissingRequiredSignature);
        }
    }

    let mut counter = 0;
    for (signer, _) in key_list.keys.iter().filter(|(_, is_signer)| *is_signer) {
        counter += 1;
        if signer != config_keyed_account.unsigned_key() {
            let signer_account =
                keyed_account_at_index(keyed_accounts, counter + 1).map_err(|_| {
                    ic_msg!(
                        invoke_context,
                        "account {:?} is not in account list",
                        signer,
                    );
                    InstructionError::MissingRequiredSignature
                })?;
            let signer_key = signer_account.signer_key();
            if signer_key.is_none() {
                ic_msg!(
                    invoke_context,
                    "account {:?} signer_key().is_none()",
                    signer
                );
                return Err(InstructionError::MissingRequiredSignature);
            }
            if signer_key.unwrap() != signer {
                ic_msg!(
                    invoke_context,
                    "account[{:?}].signer_key() does not match Config data)",
                    counter + 1
                );
                return Err(InstructionError::MissingRequiredSignature);
            }
            // If Config account is already initialized, update signatures must match Config data
            if !current_data.keys.is_empty()
                && !current_signer_keys.iter().any(|pubkey| pubkey == signer)
            {
                ic_msg!(
                    invoke_context,
                    "account {:?} is not in stored signer list",
                    signer
                );
                return Err(InstructionError::MissingRequiredSignature);
            }
        } else if config_keyed_account.signer_key().is_none() {
            ic_msg!(invoke_context, "account[0].signer_key().is_none()");
            return Err(InstructionError::MissingRequiredSignature);
        }
    }

    if invoke_context
        .feature_set
        .is_active(&feature_set::dedupe_config_program_signers::id())
    {
        let total_new_keys = key_list.keys.len();
        let unique_new_keys = key_list.keys.into_iter().collect::<BTreeSet<_>>();
        if unique_new_keys.len() != total_new_keys {
            ic_msg!(invoke_context, "new config contains duplicate keys");
            return Err(InstructionError::InvalidArgument);
        }
    }

    // Check for Config data signers not present in incoming account update
    if current_signer_keys.len() > counter {
        ic_msg!(
            invoke_context,
            "too few signers: {:?}; expected: {:?}",
            counter,
            current_signer_keys.len()
        );
        return Err(InstructionError::MissingRequiredSignature);
    }

    if config_keyed_account.data_len()? < data.len() {
        ic_msg!(invoke_context, "instruction data too large");
        return Err(InstructionError::InvalidInstructionData);
    }

    config_keyed_account
        .try_account_ref_mut()?
        .data_as_mut_slice()[..data.len()]
        .copy_from_slice(data);
    Ok(())
}
