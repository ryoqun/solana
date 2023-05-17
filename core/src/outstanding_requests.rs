use {
    crate::request_response::RequestResponse,
    lru::LruCache,
    rand::{thread_rng, Rng},
    solana_ledger::shred::Nonce,
};

pub const DEFAULT_REQUEST_EXPIRATION_MS: u64 = 60_000;

pub struct OutstandingRequests<T> {
    requests: LruCache<Nonce, RequestStatus<T>>,
}

impl<T, S> OutstandingRequests<T>
where
    T: RequestResponse<Response = S>,
{
    // Returns boolean indicating whether sufficient time has passed for a request with
    // the given timestamp to be made
    pub fn add_request(&mut self, request: T, now: u64) -> Nonce {
        let num_expected_responses = request.num_expected_responses();
        let nonce = thread_rng().gen_range(0, Nonce::MAX);
        self.requests.put(
            nonce,
            RequestStatus {
                expire_timestamp: now + DEFAULT_REQUEST_EXPIRATION_MS,
                num_expected_responses,
                request,
            },
        );
        nonce
    }

    pub fn register_response<R>(
        &mut self,
        nonce: u32,
        response: &S,
        now: u64,
        // runs if the response was valid
        success_fn: impl Fn(&T) -> R,
    ) -> Option<R> {
        let (response, should_delete) = self
            .requests
            .get_mut(&nonce)
            .map(|status| {
                if status.num_expected_responses > 0
                    && now < status.expire_timestamp
                    && status.request.verify_response(response)
                {
                    status.num_expected_responses -= 1;
                    (
                        Some(success_fn(&status.request)),
                        status.num_expected_responses == 0,
                    )
                } else {
                    (None, true)
                }
            })
            .unwrap_or((None, false));

        if should_delete {
            self.requests
                .pop(&nonce)
                .expect("Delete must delete existing object");
        }

        response
    }
}

impl<T> Default for OutstandingRequests<T> {
    fn default() -> Self {
        Self {
            requests: LruCache::new(16 * 1024),
        }
    }
}

pub struct RequestStatus<T> {
    expire_timestamp: u64,
    num_expected_responses: u32,
    request: T,
}
