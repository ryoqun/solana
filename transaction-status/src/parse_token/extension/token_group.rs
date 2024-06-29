use {
    super::*,
    spl_token_group_interface::instruction::{
        InitializeGroup, TokenGroupInstruction, UpdateGroupAuthority, UpdateGroupMaxSize,
    },
};

pub(in crate::parse_token) fn parse_token_group_instruction(
    instruction: &TokenGroupInstruction,
    account_indexes: &[u8],
    account_keys: &AccountKeys,
) -> Result<ParsedInstructionEnum, ParseInstructionError> {
    match instruction {
        TokenGroupInstruction::InitializeGroup(group) => {
            check_num_token_accounts(account_indexes, 3)?;
            let InitializeGroup {
                max_size,
                update_authority,
            } = group;
            let value = json!({
                "group": account_keys[account_indexes[0] as usize].to_string(),
                "maxSize": u32::from(*max_size),
                "mint": account_keys[account_indexes[1] as usize].to_string(),
                "mintAuthority": account_keys[account_indexes[2] as usize].to_string(),
                "updateAuthority": Option::<Pubkey>::from(*update_authority).map(|v| v.to_string())
            });
            Ok(ParsedInstructionEnum {
                instruction_type: "initializeTokenGroup".to_string(),
                info: value,
            })
        }
        TokenGroupInstruction::UpdateGroupMaxSize(update) => {
            check_num_token_accounts(account_indexes, 2)?;
            let UpdateGroupMaxSize { max_size } = update;
            let value = json!({
                "group": account_keys[account_indexes[0] as usize].to_string(),
                "maxSize": u32::from(*max_size),
                "updateAuthority": account_keys[account_indexes[1] as usize].to_string(),
            });
            Ok(ParsedInstructionEnum {
                instruction_type: "updateTokenGroupMaxSize".to_string(),
                info: value,
            })
        }
        TokenGroupInstruction::UpdateGroupAuthority(update) => {
            check_num_token_accounts(account_indexes, 2)?;
            let UpdateGroupAuthority { new_authority } = update;
            let value = json!({
                "group": account_keys[account_indexes[0] as usize].to_string(),
                "updateAuthority": account_keys[account_indexes[1] as usize].to_string(),
                "newAuthority": Option::<Pubkey>::from(*new_authority).map(|v| v.to_string())
            });
            Ok(ParsedInstructionEnum {
                instruction_type: "updateTokenGroupAuthority".to_string(),
                info: value,
            })
        }
        TokenGroupInstruction::InitializeMember(_) => {
            check_num_token_accounts(account_indexes, 5)?;
            let value = json!({
                "member": account_keys[account_indexes[0] as usize].to_string(),
                "memberMint": account_keys[account_indexes[1] as usize].to_string(),
                "memberMintAuthority": account_keys[account_indexes[2] as usize].to_string(),
                "group": account_keys[account_indexes[3] as usize].to_string(),
                "groupUpdateAuthority": account_keys[account_indexes[4] as usize].to_string(),
            });
            Ok(ParsedInstructionEnum {
                instruction_type: "initializeTokenGroupMember".to_string(),
                info: value,
            })
        }
    }
}
