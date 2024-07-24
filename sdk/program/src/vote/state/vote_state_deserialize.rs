use {
    super::{MAX_EPOCH_CREDITS_HISTORY, MAX_LOCKOUT_HISTORY},
    crate::{
        instruction::InstructionError,
        pubkey::Pubkey,
        serialize_utils::cursor::*,
        vote::{
            authorized_voters::AuthorizedVoters,
            state::{BlockTimestamp, LandedVote, Lockout, VoteState, MAX_ITEMS},
        },
    },
    std::{collections::VecDeque, io::Cursor, ptr::addr_of_mut},
};

pub(super) fn deserialize_vote_state_into(
    cursor: &mut Cursor<&[u8]>,
    vote_state: *mut VoteState,
    has_latency: bool,
) -> Result<(), InstructionError> {
    unsafe {
        addr_of_mut!((*vote_state).node_pubkey).write(read_pubkey(cursor)?);
        addr_of_mut!((*vote_state).authorized_withdrawer).write(read_pubkey(cursor)?);
        addr_of_mut!((*vote_state).commission).write(read_u8(cursor)?);
    }
    let votes = read_votes(cursor, has_latency)?;
    unsafe {
        addr_of_mut!((*vote_state).root_slot).write(read_option_u64(cursor)?);
    }
    let authorized_voters = read_authorized_voters(cursor)?;
    read_prior_voters_into(cursor, vote_state)?;
    let epoch_credits = read_epoch_credits(cursor)?;
    read_last_timestamp_into(cursor, vote_state)?;

    // Defer writing the collections until we know we're going to succeed. This way if we fail we
    // still drop the collections and don't leak memory.
    unsafe {
        addr_of_mut!((*vote_state).votes).write(votes);
        addr_of_mut!((*vote_state).authorized_voters).write(authorized_voters);
        addr_of_mut!((*vote_state).epoch_credits).write(epoch_credits);
    }

    Ok(())
}

fn read_votes<T: AsRef<[u8]>>(
    cursor: &mut Cursor<T>,
    has_latency: bool,
) -> Result<VecDeque<LandedVote>, InstructionError> {
    let vote_count = read_u64(cursor)? as usize;
    let mut votes = VecDeque::with_capacity(vote_count.min(MAX_LOCKOUT_HISTORY));

    for _ in 0..vote_count {
        let latency = if has_latency { read_u8(cursor)? } else { 0 };

        let slot = read_u64(cursor)?;
        let confirmation_count = read_u32(cursor)?;
        let lockout = Lockout::new_with_confirmation_count(slot, confirmation_count);

        votes.push_back(LandedVote { latency, lockout });
    }

    Ok(votes)
}

fn read_authorized_voters<T: AsRef<[u8]>>(
    cursor: &mut Cursor<T>,
) -> Result<AuthorizedVoters, InstructionError> {
    let authorized_voter_count = read_u64(cursor)?;
    let mut authorized_voters = AuthorizedVoters::default();

    for _ in 0..authorized_voter_count {
        let epoch = read_u64(cursor)?;
        let authorized_voter = read_pubkey(cursor)?;
        authorized_voters.insert(epoch, authorized_voter);
    }

    Ok(authorized_voters)
}

fn read_prior_voters_into<T: AsRef<[u8]>>(
    cursor: &mut Cursor<T>,
    vote_state: *mut VoteState,
) -> Result<(), InstructionError> {
    unsafe {
        let prior_voters = addr_of_mut!((*vote_state).prior_voters);
        let prior_voters_buf = addr_of_mut!((*prior_voters).buf) as *mut (Pubkey, u64, u64);

        for i in 0..MAX_ITEMS {
            let prior_voter = read_pubkey(cursor)?;
            let from_epoch = read_u64(cursor)?;
            let until_epoch = read_u64(cursor)?;

            prior_voters_buf
                .add(i)
                .write((prior_voter, from_epoch, until_epoch));
        }

        (*vote_state).prior_voters.idx = read_u64(cursor)? as usize;
        (*vote_state).prior_voters.is_empty = read_bool(cursor)?;
    }
    Ok(())
}

fn read_epoch_credits<T: AsRef<[u8]>>(
    cursor: &mut Cursor<T>,
) -> Result<Vec<(u64, u64, u64)>, InstructionError> {
    let epoch_credit_count = read_u64(cursor)? as usize;
    let mut epoch_credits = Vec::with_capacity(epoch_credit_count.min(MAX_EPOCH_CREDITS_HISTORY));

    for _ in 0..epoch_credit_count {
        let epoch = read_u64(cursor)?;
        let credits = read_u64(cursor)?;
        let prev_credits = read_u64(cursor)?;
        epoch_credits.push((epoch, credits, prev_credits));
    }

    Ok(epoch_credits)
}

fn read_last_timestamp_into<T: AsRef<[u8]>>(
    cursor: &mut Cursor<T>,
    vote_state: *mut VoteState,
) -> Result<(), InstructionError> {
    let slot = read_u64(cursor)?;
    let timestamp = read_i64(cursor)?;

    let last_timestamp = BlockTimestamp { slot, timestamp };

    unsafe {
        addr_of_mut!((*vote_state).last_timestamp).write(last_timestamp);
    }

    Ok(())
}
