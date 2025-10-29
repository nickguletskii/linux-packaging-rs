use crate::error;
use crate::error::DebianError;
use pgp::crypto::hash::Hasher;
use pgp_cleartext::CleartextHasher;
use std::fmt::Formatter;

/// Checksum type / digest mechanism used for content files.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DebChecksumType {
    /// MD5.
    Md5,

    /// SHA-1.
    Sha1,

    /// SHA-256.
    Sha256,
}

impl DebChecksumType {
    /// Emit variants in their preferred usage order.
    pub fn preferred_order() -> impl Iterator<Item = DebChecksumType> {
        [Self::Sha256, Self::Sha1, Self::Md5].into_iter()
    }

    /// Name of the control field in `Release` files holding this variant type.
    pub fn field_name(&self) -> &'static str {
        match self {
            Self::Md5 => "MD5Sum",
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
        }
    }

    /// Obtain a new hasher for this checksum flavor.
    pub fn new_hasher(&self) -> Box<dyn pgp::crypto::hash::Hasher + Send> {
        Box::new(match self {
            Self::Md5 => CleartextHasher::md5(),
            Self::Sha1 => CleartextHasher::sha1(),
            Self::Sha256 => CleartextHasher::sha256(),
        })
    }
}

/// Represents a content digest.
#[derive(Clone, Eq, PartialEq, PartialOrd)]
pub enum DebContentDigest {
    /// An MD5 digest.
    Md5(Vec<u8>),
    /// A SHA-1 digest.
    Sha1(Vec<u8>),
    /// A SHA-256 digest.
    Sha256(Vec<u8>),
}

impl std::fmt::Debug for DebContentDigest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Md5(data) => write!(f, "Md5({})", hex::encode(data)),
            Self::Sha1(data) => write!(f, "Sha1({})", hex::encode(data)),
            Self::Sha256(data) => write!(f, "Sha256({})", hex::encode(data)),
        }
    }
}

impl DebContentDigest {
    /// Create a new MD5 instance by parsing a hex digest.
    pub fn md5_hex(digest: &str) -> error::Result<Self> {
        Self::from_hex_digest(DebChecksumType::Md5, digest)
    }

    /// Create a new SHA-1 instance by parsing a hex digest.
    pub fn sha1_hex(digest: &str) -> error::Result<Self> {
        Self::from_hex_digest(DebChecksumType::Sha1, digest)
    }

    /// Create a new SHA-256 instance by parsing a hex digest.
    pub fn sha256_hex(digest: &str) -> error::Result<Self> {
        Self::from_hex_digest(DebChecksumType::Sha256, digest)
    }

    /// Obtain an instance by parsing a hex string as a [DebChecksumType].
    pub fn from_hex_digest(checksum: DebChecksumType, digest: &str) -> error::Result<Self> {
        let digest = hex::decode(digest)
            .map_err(|e| DebianError::ContentDigestBadHex(digest.to_string(), e))?;

        Ok(match checksum {
            DebChecksumType::Md5 => Self::Md5(digest),
            DebChecksumType::Sha1 => Self::Sha1(digest),
            DebChecksumType::Sha256 => Self::Sha256(digest),
        })
    }

    /// Create a new hasher matching for the type of this digest.
    pub fn new_hasher(&self) -> Box<dyn Hasher + Send> {
        Box::new(match self {
            Self::Md5(_) => CleartextHasher::md5(),
            Self::Sha1(_) => CleartextHasher::sha1(),
            Self::Sha256(_) => CleartextHasher::sha256(),
        })
    }

    /// Obtain the digest bytes for this content digest.
    pub fn digest_bytes(&self) -> &[u8] {
        match self {
            Self::Md5(x) => x,
            Self::Sha1(x) => x,
            Self::Sha256(x) => x,
        }
    }

    /// Obtain the hex encoded content digest.
    pub fn digest_hex(&self) -> String {
        hex::encode(self.digest_bytes())
    }

    /// Obtain the [DebChecksumType] for this digest.
    pub fn checksum_type(&self) -> DebChecksumType {
        match self {
            Self::Md5(_) => DebChecksumType::Md5,
            Self::Sha1(_) => DebChecksumType::Sha1,
            Self::Sha256(_) => DebChecksumType::Sha256,
        }
    }

    /// Obtain the name of the field in `[In]Release` files that holds this digest type.
    ///
    /// This also corresponds to the directory name for `by-hash` paths.
    pub fn release_field_name(&self) -> &'static str {
        self.checksum_type().field_name()
    }
}

/// Represents a content digest.
#[derive(Clone, Eq, PartialEq, PartialOrd)]
pub enum AnyContentDigest {
    /// An MD5 digest.
    Md5(Vec<u8>),
    /// A SHA-1 digest.
    Sha1(Vec<u8>),
    /// A SHA-256 digest.
    Sha256(Vec<u8>),
    /// A SHA-384 digest.
    Sha384(Vec<u8>),
    /// A SHA-512 digest.
    Sha512(Vec<u8>),
}

impl std::fmt::Debug for AnyContentDigest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Md5(data) => write!(f, "Md5({})", hex::encode(data)),
            Self::Sha1(data) => write!(f, "Sha1({})", hex::encode(data)),
            Self::Sha256(data) => write!(f, "Sha256({})", hex::encode(data)),
            Self::Sha384(data) => write!(f, "Sha384({})", hex::encode(data)),
            Self::Sha512(data) => write!(f, "Sha512({})", hex::encode(data)),
        }
    }
}

impl AnyContentDigest {
    /// Create a new MD5 instance by parsing a hex digest.
    pub fn md5_hex(digest: &str) -> error::Result<Self> {
        Self::from_hex_digest(AnyChecksumType::Md5, digest)
    }

    /// Create a new SHA-1 instance by parsing a hex digest.
    pub fn sha1_hex(digest: &str) -> error::Result<Self> {
        Self::from_hex_digest(AnyChecksumType::Sha1, digest)
    }

    /// Create a new SHA-256 instance by parsing a hex digest.
    pub fn sha256_hex(digest: &str) -> error::Result<Self> {
        Self::from_hex_digest(AnyChecksumType::Sha256, digest)
    }

    /// Create a new SHA-384 instance by parsing a hex digest.
    pub fn sha384_hex(digest: &str) -> error::Result<Self> {
        Self::from_hex_digest(AnyChecksumType::Sha384, digest)
    }

    /// Create a new SHA-512 instance by parsing a hex digest.
    pub fn sha512_hex(digest: &str) -> error::Result<Self> {
        Self::from_hex_digest(AnyChecksumType::Sha512, digest)
    }

    /// Obtain an instance by parsing a hex string as a [DebChecksumType].
    pub fn from_hex_digest(checksum: AnyChecksumType, digest: &str) -> error::Result<Self> {
        let digest = hex::decode(digest)
            .map_err(|e| DebianError::ContentDigestBadHex(digest.to_string(), e))?;

        Ok(match checksum {
            AnyChecksumType::Md5 => Self::Md5(digest),
            AnyChecksumType::Sha1 => Self::Sha1(digest),
            AnyChecksumType::Sha256 => Self::Sha256(digest),
            AnyChecksumType::Sha384 => Self::Sha384(digest),
            AnyChecksumType::Sha512 => Self::Sha512(digest),
        })
    }

    /// Create a new hasher matching for the type of this digest.
    pub fn new_hasher(&self) -> Box<dyn Hasher + Send> {
        Box::new(match self {
            Self::Md5(_) => CleartextHasher::md5(),
            Self::Sha1(_) => CleartextHasher::sha1(),
            Self::Sha256(_) => CleartextHasher::sha256(),
            Self::Sha384(_) => CleartextHasher::sha384(),
            Self::Sha512(_) => CleartextHasher::sha512(),
        })
    }

    /// Obtain the digest bytes for this content digest.
    pub fn digest_bytes(&self) -> &[u8] {
        match self {
            Self::Md5(x) => x,
            Self::Sha1(x) => x,
            Self::Sha256(x) => x,
            Self::Sha384(x) => x,
            Self::Sha512(x) => x,
        }
    }

    /// Obtain the hex encoded content digest.
    pub fn digest_hex(&self) -> String {
        hex::encode(self.digest_bytes())
    }

    /// Obtain the [AnyChecksumType] for this digest.
    pub fn checksum_type(&self) -> AnyChecksumType {
        match self {
            Self::Md5(_) => AnyChecksumType::Md5,
            Self::Sha1(_) => AnyChecksumType::Sha1,
            Self::Sha256(_) => AnyChecksumType::Sha256,
            Self::Sha384(_) => AnyChecksumType::Sha384,
            Self::Sha512(_) => AnyChecksumType::Sha512,
        }
    }

    /// Obtain the name of the field in `[In]Release` files that holds this digest type.
    ///
    /// This also corresponds to the directory name for `by-hash` paths.
    pub fn release_field_name(&self) -> &'static str {
        self.checksum_type().field_name()
    }
}

impl From<DebContentDigest> for AnyContentDigest {
    fn from(value: DebContentDigest) -> Self {
        match value {
            DebContentDigest::Md5(x) => AnyContentDigest::Md5(x),
            DebContentDigest::Sha1(x) => AnyContentDigest::Sha1(x),
            DebContentDigest::Sha256(x) => AnyContentDigest::Sha256(x),
        }
    }
}

impl TryFrom<AnyContentDigest> for DebContentDigest {
    type Error = AnyContentDigest;

    fn try_from(value: AnyContentDigest) -> std::result::Result<Self, Self::Error> {
        match value {
            AnyContentDigest::Md5(x) => Ok(DebContentDigest::Md5(x)),
            AnyContentDigest::Sha1(x) => Ok(DebContentDigest::Sha1(x)),
            AnyContentDigest::Sha256(x) => Ok(DebContentDigest::Sha256(x)),
            AnyContentDigest::Sha384(x) => Err(AnyContentDigest::Sha384(x)),
            AnyContentDigest::Sha512(x) => Err(AnyContentDigest::Sha512(x)),
        }
    }
}

/// Checksum type / digest mechanism used in a release file.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AnyChecksumType {
    /// MD5.
    Md5,

    /// SHA-1.
    Sha1,

    /// SHA-256.
    Sha256,

    /// SHA-384.
    Sha384,

    /// SHA-512.
    Sha512,
}

impl AnyChecksumType {
    /// Emit variants in their preferred usage order.
    pub fn preferred_order() -> impl Iterator<Item = AnyChecksumType> {
        [
            Self::Sha256,
            Self::Sha1,
            Self::Md5,
            Self::Sha512,
            Self::Sha384,
        ]
        .into_iter()
    }

    /// Name of the control field in `Release` files holding this variant type.
    pub fn field_name(&self) -> &'static str {
        match self {
            Self::Md5 => "MD5Sum",
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha384 => "SHA384",
            Self::Sha512 => "SHA512",
        }
    }

    /// Obtain a new hasher for this checksum flavor.
    pub fn new_hasher(&self) -> Box<dyn pgp::crypto::hash::Hasher + Send> {
        Box::new(match self {
            Self::Md5 => CleartextHasher::md5(),
            Self::Sha1 => CleartextHasher::sha1(),
            Self::Sha256 => CleartextHasher::sha256(),
            Self::Sha384 => CleartextHasher::sha384(),
            Self::Sha512 => CleartextHasher::sha512(),
        })
    }
}

impl From<DebChecksumType> for AnyChecksumType {
    fn from(value: DebChecksumType) -> Self {
        match value {
            DebChecksumType::Md5 => AnyChecksumType::Md5,
            DebChecksumType::Sha1 => AnyChecksumType::Sha1,
            DebChecksumType::Sha256 => AnyChecksumType::Sha256,
        }
    }
}
