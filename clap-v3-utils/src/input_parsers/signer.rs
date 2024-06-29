use {
    crate::keypair::{
        keypair_from_seed_phrase, keypair_from_source, pubkey_from_path, pubkey_from_source,
        resolve_signer_from_path, resolve_signer_from_source, signer_from_path, signer_from_source,
        ASK_KEYWORD, SKIP_SEED_PHRASE_VALIDATION_ARG,
    },
    clap::{builder::ValueParser, ArgMatches},
    solana_remote_wallet::{
        locator::{Locator as RemoteWalletLocator, LocatorError as RemoteWalletLocatorError},
        remote_wallet::RemoteWalletManager,
    },
    solana_sdk::{
        derivation_path::{DerivationPath, DerivationPathError},
        pubkey::Pubkey,
        signature::{read_keypair_file, Keypair, Signature, Signer},
    },
    std::{error, rc::Rc, str::FromStr},
    thiserror::Error,
};

const SIGNER_SOURCE_PROMPT: &str = "prompt";
const SIGNER_SOURCE_FILEPATH: &str = "file";
const SIGNER_SOURCE_USB: &str = "usb";
const SIGNER_SOURCE_STDIN: &str = "stdin";
const SIGNER_SOURCE_PUBKEY: &str = "pubkey";

#[derive(Debug, Error)]
pub enum SignerSourceError {
    #[error("unrecognized signer source")]
    UnrecognizedSource,
    #[error(transparent)]
    RemoteWalletLocatorError(#[from] RemoteWalletLocatorError),
    #[error(transparent)]
    DerivationPathError(#[from] DerivationPathError),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error("unsupported source")]
    UnsupportedSource,
}

#[derive(Clone)]
pub enum SignerSourceKind {
    Prompt,
    Filepath(String),
    Usb(RemoteWalletLocator),
    Stdin,
    Pubkey(Pubkey),
}

impl AsRef<str> for SignerSourceKind {
    fn as_ref(&self) -> &str {
        match self {
            Self::Prompt => SIGNER_SOURCE_PROMPT,
            Self::Filepath(_) => SIGNER_SOURCE_FILEPATH,
            Self::Usb(_) => SIGNER_SOURCE_USB,
            Self::Stdin => SIGNER_SOURCE_STDIN,
            Self::Pubkey(_) => SIGNER_SOURCE_PUBKEY,
        }
    }
}

impl std::fmt::Debug for SignerSourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s: &str = self.as_ref();
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone)]
pub struct SignerSource {
    pub kind: SignerSourceKind,
    pub derivation_path: Option<DerivationPath>,
    pub legacy: bool,
}

impl SignerSource {
    fn new(kind: SignerSourceKind) -> Self {
        Self {
            kind,
            derivation_path: None,
            legacy: false,
        }
    }

    fn new_legacy(kind: SignerSourceKind) -> Self {
        Self {
            kind,
            derivation_path: None,
            legacy: true,
        }
    }

    pub fn try_get_keypair(
        matches: &ArgMatches,
        name: &str,
    ) -> Result<Option<Keypair>, Box<dyn error::Error>> {
        let source = matches.try_get_one::<Self>(name)?;
        if let Some(source) = source {
            keypair_from_source(matches, source, name, true).map(Some)
        } else {
            Ok(None)
        }
    }

    pub fn try_get_keypairs(
        matches: &ArgMatches,
        name: &str,
    ) -> Result<Option<Vec<Keypair>>, Box<dyn error::Error>> {
        let sources = matches.try_get_many::<Self>(name)?;
        if let Some(sources) = sources {
            let keypairs = sources
                .filter_map(|source| keypair_from_source(matches, source, name, true).ok())
                .collect();
            Ok(Some(keypairs))
        } else {
            Ok(None)
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn try_get_signer(
        matches: &ArgMatches,
        name: &str,
        wallet_manager: &mut Option<Rc<RemoteWalletManager>>,
    ) -> Result<Option<(Box<dyn Signer>, Pubkey)>, Box<dyn error::Error>> {
        let source = matches.try_get_one::<Self>(name)?;
        if let Some(source) = source {
            let signer = signer_from_source(matches, source, name, wallet_manager)?;
            let signer_pubkey = signer.pubkey();
            Ok(Some((signer, signer_pubkey)))
        } else {
            Ok(None)
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn try_get_signers(
        matches: &ArgMatches,
        name: &str,
        wallet_manager: &mut Option<Rc<RemoteWalletManager>>,
    ) -> Result<Option<Vec<(Box<dyn Signer>, Pubkey)>>, Box<dyn error::Error>> {
        let sources = matches.try_get_many::<Self>(name)?;
        if let Some(sources) = sources {
            let signers = sources
                .filter_map(|source| {
                    let signer = signer_from_source(matches, source, name, wallet_manager).ok()?;
                    let signer_pubkey = signer.pubkey();
                    Some((signer, signer_pubkey))
                })
                .collect();
            Ok(Some(signers))
        } else {
            Ok(None)
        }
    }

    pub fn try_get_pubkey(
        matches: &ArgMatches,
        name: &str,
        wallet_manager: &mut Option<Rc<RemoteWalletManager>>,
    ) -> Result<Option<Pubkey>, Box<dyn error::Error>> {
        let source = matches.try_get_one::<Self>(name)?;
        if let Some(source) = source {
            pubkey_from_source(matches, source, name, wallet_manager).map(Some)
        } else {
            Ok(None)
        }
    }

    pub fn try_get_pubkeys(
        matches: &ArgMatches,
        name: &str,
        wallet_manager: &mut Option<Rc<RemoteWalletManager>>,
    ) -> Result<Option<Vec<Pubkey>>, Box<dyn std::error::Error>> {
        let sources = matches.try_get_many::<Self>(name)?;
        if let Some(sources) = sources {
            let pubkeys = sources
                .filter_map(|source| pubkey_from_source(matches, source, name, wallet_manager).ok())
                .collect();
            Ok(Some(pubkeys))
        } else {
            Ok(None)
        }
    }

    pub fn try_resolve(
        matches: &ArgMatches,
        name: &str,
        wallet_manager: &mut Option<Rc<RemoteWalletManager>>,
    ) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let source = matches.try_get_one::<Self>(name)?;
        if let Some(source) = source {
            resolve_signer_from_source(matches, source, name, wallet_manager)
        } else {
            Ok(None)
        }
    }

    pub fn parse<S: AsRef<str>>(source: S) -> Result<Self, SignerSourceError> {
        let source = source.as_ref();
        let source = {
            #[cfg(target_family = "windows")]
            {
                // trim matched single-quotes since cmd.exe won't
                let mut source = source;
                while let Some(trimmed) = source.strip_prefix('\'') {
                    source = if let Some(trimmed) = trimmed.strip_suffix('\'') {
                        trimmed
                    } else {
                        break;
                    }
                }
                source.replace('\\', "/")
            }
            #[cfg(not(target_family = "windows"))]
            {
                source.to_string()
            }
        };
        match uriparse::URIReference::try_from(source.as_str()) {
            Err(_) => Err(SignerSourceError::UnrecognizedSource),
            Ok(uri) => {
                if let Some(scheme) = uri.scheme() {
                    let scheme = scheme.as_str().to_ascii_lowercase();
                    match scheme.as_str() {
                        SIGNER_SOURCE_PROMPT => Ok(SignerSource {
                            kind: SignerSourceKind::Prompt,
                            derivation_path: DerivationPath::from_uri_any_query(&uri)?,
                            legacy: false,
                        }),
                        SIGNER_SOURCE_FILEPATH => Ok(SignerSource::new(
                            SignerSourceKind::Filepath(uri.path().to_string()),
                        )),
                        SIGNER_SOURCE_USB => Ok(SignerSource {
                            kind: SignerSourceKind::Usb(RemoteWalletLocator::new_from_uri(&uri)?),
                            derivation_path: DerivationPath::from_uri_key_query(&uri)?,
                            legacy: false,
                        }),
                        SIGNER_SOURCE_STDIN => Ok(SignerSource::new(SignerSourceKind::Stdin)),
                        _ => {
                            #[cfg(target_family = "windows")]
                            // On Windows, an absolute path's drive letter will be parsed as the URI
                            // scheme. Assume a filepath source in case of a single character shceme.
                            if scheme.len() == 1 {
                                return Ok(SignerSource::new(SignerSourceKind::Filepath(source)));
                            }
                            Err(SignerSourceError::UnrecognizedSource)
                        }
                    }
                } else {
                    match source.as_str() {
                        STDOUT_OUTFILE_TOKEN => Ok(SignerSource::new(SignerSourceKind::Stdin)),
                        ASK_KEYWORD => Ok(SignerSource::new_legacy(SignerSourceKind::Prompt)),
                        _ => match Pubkey::from_str(source.as_str()) {
                            Ok(pubkey) => Ok(SignerSource::new(SignerSourceKind::Pubkey(pubkey))),
                            Err(_) => std::fs::metadata(source.as_str())
                                .map(|_| SignerSource::new(SignerSourceKind::Filepath(source)))
                                .map_err(|err| err.into()),
                        },
                    }
                }
            }
        }
    }
}

// Sentinel value used to indicate to write to screen instead of file
pub const STDOUT_OUTFILE_TOKEN: &str = "-";

#[derive(Debug, Default)]
pub struct SignerSourceParserBuilder {
    allow_prompt: bool,
    allow_file_path: bool,
    allow_usb: bool,
    allow_stdin: bool,
    allow_pubkey: bool,
    allow_legacy: bool,
}

impl SignerSourceParserBuilder {
    pub fn allow_all(mut self) -> Self {
        self.allow_prompt = true;
        self.allow_file_path = true;
        self.allow_usb = true;
        self.allow_stdin = true;
        self.allow_pubkey = true;
        self.allow_legacy = true;
        self
    }

    pub fn allow_prompt(mut self) -> Self {
        self.allow_prompt = true;
        self
    }

    pub fn allow_file_path(mut self) -> Self {
        self.allow_file_path = true;
        self
    }

    pub fn allow_usb(mut self) -> Self {
        self.allow_usb = true;
        self
    }

    pub fn allow_stdin(mut self) -> Self {
        self.allow_stdin = true;
        self
    }

    pub fn allow_pubkey(mut self) -> Self {
        self.allow_pubkey = true;
        self
    }

    pub fn allow_legacy(mut self) -> Self {
        self.allow_legacy = true;
        self
    }

    pub fn build(self) -> ValueParser {
        ValueParser::from(
            move |arg: &str| -> Result<SignerSource, SignerSourceError> {
                let signer_source = SignerSource::parse(arg)?;
                if !self.allow_legacy && signer_source.legacy {
                    return Err(SignerSourceError::UnsupportedSource);
                }
                match signer_source.kind {
                    SignerSourceKind::Prompt if self.allow_prompt => Ok(signer_source),
                    SignerSourceKind::Filepath(_) if self.allow_file_path => Ok(signer_source),
                    SignerSourceKind::Usb(_) if self.allow_usb => Ok(signer_source),
                    SignerSourceKind::Stdin if self.allow_stdin => Ok(signer_source),
                    SignerSourceKind::Pubkey(_) if self.allow_pubkey => Ok(signer_source),
                    _ => Err(SignerSourceError::UnsupportedSource),
                }
            },
        )
    }
}

// Return the keypair for an argument with filename `name` or `None` if not present wrapped inside `Result`.
pub fn try_keypair_of(
    matches: &ArgMatches,
    name: &str,
) -> Result<Option<Keypair>, Box<dyn error::Error>> {
    if let Some(value) = matches.try_get_one::<String>(name)? {
        extract_keypair(matches, name, value)
    } else {
        Ok(None)
    }
}

pub fn try_keypairs_of(
    matches: &ArgMatches,
    name: &str,
) -> Result<Option<Vec<Keypair>>, Box<dyn error::Error>> {
    Ok(matches.try_get_many::<String>(name)?.map(|values| {
        values
            .filter_map(|value| extract_keypair(matches, name, value).ok().flatten())
            .collect()
    }))
}

fn extract_keypair(
    matches: &ArgMatches,
    name: &str,
    path: &str,
) -> Result<Option<Keypair>, Box<dyn error::Error>> {
    if path == ASK_KEYWORD {
        let skip_validation = matches.try_contains_id(SKIP_SEED_PHRASE_VALIDATION_ARG.name)?;
        keypair_from_seed_phrase(name, skip_validation, true, None, true).map(Some)
    } else {
        read_keypair_file(path).map(Some)
    }
}

// Return a `Result` wrapped pubkey for an argument that can itself be parsed into a pubkey,
// or is a filename that can be read as a keypair
pub fn try_pubkey_of(
    matches: &ArgMatches,
    name: &str,
) -> Result<Option<Pubkey>, Box<dyn error::Error>> {
    if let Some(pubkey) = matches.try_get_one::<Pubkey>(name)? {
        Ok(Some(*pubkey))
    } else {
        Ok(try_keypair_of(matches, name)?.map(|keypair| keypair.pubkey()))
    }
}

pub fn try_pubkeys_of(
    matches: &ArgMatches,
    name: &str,
) -> Result<Option<Vec<Pubkey>>, Box<dyn error::Error>> {
    if let Some(pubkey_strings) = matches.try_get_many::<String>(name)? {
        let mut pubkeys = Vec::with_capacity(pubkey_strings.len());
        for pubkey_string in pubkey_strings {
            pubkeys.push(pubkey_string.parse::<Pubkey>()?);
        }
        Ok(Some(pubkeys))
    } else {
        Ok(None)
    }
}

// Return pubkey/signature pairs for a string of the form pubkey=signature
#[deprecated(since = "2.0.0", note = "Please use `try_pubkeys_sigs_of` instead")]
#[allow(deprecated)]
pub fn pubkeys_sigs_of(matches: &ArgMatches, name: &str) -> Option<Vec<(Pubkey, Signature)>> {
    matches.values_of(name).map(|values| {
        values
            .map(|pubkey_signer_string| {
                let mut signer = pubkey_signer_string.split('=');
                let key = Pubkey::from_str(signer.next().unwrap()).unwrap();
                let sig = Signature::from_str(signer.next().unwrap()).unwrap();
                (key, sig)
            })
            .collect()
    })
}

// Return pubkey/signature pairs for a string of the form pubkey=signature wrapped inside `Result`
#[allow(clippy::type_complexity)]
pub fn try_pubkeys_sigs_of(
    matches: &ArgMatches,
    name: &str,
) -> Result<Option<Vec<(Pubkey, Signature)>>, Box<dyn error::Error>> {
    if let Some(pubkey_signer_strings) = matches.try_get_many::<String>(name)? {
        let mut pubkey_sig_pairs = Vec::with_capacity(pubkey_signer_strings.len());
        for pubkey_signer_string in pubkey_signer_strings {
            let (pubkey_string, sig_string) = pubkey_signer_string
                .split_once('=')
                .ok_or("failed to parse `pubkey=signature` pair")?;
            let pubkey = Pubkey::from_str(pubkey_string)?;
            let sig = Signature::from_str(sig_string)?;
            pubkey_sig_pairs.push((pubkey, sig));
        }
        Ok(Some(pubkey_sig_pairs))
    } else {
        Ok(None)
    }
}

// Return a signer from matches at `name`
#[allow(clippy::type_complexity)]
pub fn signer_of(
    matches: &ArgMatches,
    name: &str,
    wallet_manager: &mut Option<Rc<RemoteWalletManager>>,
) -> Result<(Option<Box<dyn Signer>>, Option<Pubkey>), Box<dyn std::error::Error>> {
    if let Some(location) = matches.try_get_one::<String>(name)? {
        let signer = signer_from_path(matches, location, name, wallet_manager)?;
        let signer_pubkey = signer.pubkey();
        Ok((Some(signer), Some(signer_pubkey)))
    } else {
        Ok((None, None))
    }
}

pub fn pubkey_of_signer(
    matches: &ArgMatches,
    name: &str,
    wallet_manager: &mut Option<Rc<RemoteWalletManager>>,
) -> Result<Option<Pubkey>, Box<dyn std::error::Error>> {
    if let Some(location) = matches.try_get_one::<String>(name)? {
        Ok(Some(pubkey_from_path(
            matches,
            location,
            name,
            wallet_manager,
        )?))
    } else {
        Ok(None)
    }
}

pub fn pubkeys_of_multiple_signers(
    matches: &ArgMatches,
    name: &str,
    wallet_manager: &mut Option<Rc<RemoteWalletManager>>,
) -> Result<Option<Vec<Pubkey>>, Box<dyn std::error::Error>> {
    if let Some(pubkey_matches) = matches.try_get_many::<String>(name)? {
        let mut pubkeys: Vec<Pubkey> = vec![];
        for signer in pubkey_matches {
            pubkeys.push(pubkey_from_path(matches, signer, name, wallet_manager)?);
        }
        Ok(Some(pubkeys))
    } else {
        Ok(None)
    }
}

pub fn resolve_signer(
    matches: &ArgMatches,
    name: &str,
    wallet_manager: &mut Option<Rc<RemoteWalletManager>>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    resolve_signer_from_path(
        matches,
        matches.try_get_one::<String>(name)?.unwrap(),
        name,
        wallet_manager,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PubkeySignature {
    pubkey: Pubkey,
    signature: Signature,
}
impl FromStr for PubkeySignature {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut signer = s.split('=');
        let pubkey = signer
            .next()
            .ok_or_else(|| String::from("Malformed signer string"))?;
        let pubkey = Pubkey::from_str(pubkey).map_err(|err| format!("{err}"))?;

        let signature = signer
            .next()
            .ok_or_else(|| String::from("Malformed signer string"))?;
        let signature = Signature::from_str(signature).map_err(|err| format!("{err}"))?;

        Ok(Self { pubkey, signature })
    }
}
