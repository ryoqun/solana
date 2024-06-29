use {
    super::*,
    spl_token_metadata_interface::{
        instruction::{
            Emit, Initialize, RemoveKey, TokenMetadataInstruction, UpdateAuthority, UpdateField,
        },
        state::Field,
    },
};

fn token_metadata_field_to_string(field: &Field) -> String {
    match field {
        Field::Name => "name".to_string(),
        Field::Symbol => "symbol".to_string(),
        Field::Uri => "uri".to_string(),
        Field::Key(key) => key.clone(),
    }
}

pub(in crate::parse_token) fn parse_token_metadata_instruction(
    instruction: &TokenMetadataInstruction,
    account_indexes: &[u8],
    account_keys: &AccountKeys,
) -> Result<ParsedInstructionEnum, ParseInstructionError> {
    match instruction {
        TokenMetadataInstruction::Initialize(metadata) => {
            check_num_token_accounts(account_indexes, 4)?;
            let Initialize { name, symbol, uri } = metadata;
            let value = json!({
                "metadata": account_keys[account_indexes[0] as usize].to_string(),
                "updateAuthority": account_keys[account_indexes[1] as usize].to_string(),
                "mint": account_keys[account_indexes[2] as usize].to_string(),
                "mintAuthority": account_keys[account_indexes[3] as usize].to_string(),
                "name": name,
                "symbol": symbol,
                "uri": uri,
            });
            Ok(ParsedInstructionEnum {
                instruction_type: "initializeTokenMetadata".to_string(),
                info: value,
            })
        }
        TokenMetadataInstruction::UpdateField(update) => {
            check_num_token_accounts(account_indexes, 2)?;
            let UpdateField { field, value } = update;
            let value = json!({
                "metadata": account_keys[account_indexes[0] as usize].to_string(),
                "updateAuthority": account_keys[account_indexes[1] as usize].to_string(),
                "field": token_metadata_field_to_string(field),
                "value": value,
            });
            Ok(ParsedInstructionEnum {
                instruction_type: "updateTokenMetadataField".to_string(),
                info: value,
            })
        }
        TokenMetadataInstruction::RemoveKey(remove) => {
            check_num_token_accounts(account_indexes, 2)?;
            let RemoveKey { key, idempotent } = remove;
            let value = json!({
                "metadata": account_keys[account_indexes[0] as usize].to_string(),
                "updateAuthority": account_keys[account_indexes[1] as usize].to_string(),
                "key": key,
                "idempotent": *idempotent,
            });
            Ok(ParsedInstructionEnum {
                instruction_type: "removeTokenMetadataKey".to_string(),
                info: value,
            })
        }
        TokenMetadataInstruction::UpdateAuthority(update) => {
            check_num_token_accounts(account_indexes, 2)?;
            let UpdateAuthority { new_authority } = update;
            let value = json!({
                "metadata": account_keys[account_indexes[0] as usize].to_string(),
                "updateAuthority": account_keys[account_indexes[1] as usize].to_string(),
                "newAuthority": Option::<Pubkey>::from(*new_authority).map(|v| v.to_string()),
            });
            Ok(ParsedInstructionEnum {
                instruction_type: "updateTokenMetadataAuthority".to_string(),
                info: value,
            })
        }
        TokenMetadataInstruction::Emit(emit) => {
            check_num_token_accounts(account_indexes, 1)?;
            let Emit { start, end } = emit;
            let mut value = json!({
                "metadata": account_keys[account_indexes[0] as usize].to_string(),
            });
            let map = value.as_object_mut().unwrap();
            if let Some(start) = *start {
                map.insert("start".to_string(), json!(start));
            }
            if let Some(end) = *end {
                map.insert("end".to_string(), json!(end));
            }
            Ok(ParsedInstructionEnum {
                instruction_type: "emitTokenMetadata".to_string(),
                info: value,
            })
        }
    }
}
