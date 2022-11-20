use crate::Error;
use jsonwebtoken::{
    decode, encode, get_current_timestamp, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, Error>;

pub struct Issuer {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    validation: Validation,
    iss: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Role {
    User,
    Admin,
}

#[derive(Debug)]
pub struct User {
    pub name: String,
    pub role: Role,
}

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    role: Role,
    exp: u64,
    nbf: u64,
}

impl Issuer {
    /// Create a new token issuer from the given `secret` and `iss`uer name.
    pub fn new(secret: &[u8], iss: String) -> Self {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_nbf = true;

        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
            iss,
            validation,
        }
    }

    /// Issue a new token for `sub` which may or may not have an admin role.
    pub fn issue(&self, user: User) -> Result<String> {
        let now = get_current_timestamp();

        let claims = Claims {
            sub: user.name,
            iss: self.iss.clone(),
            role: user.role,
            exp: now + 365 * 24 * 60 * 60,
            nbf: now,
        };

        let token = encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|err| Error::TokenCreation(err.to_string()))?;

        Ok(token)
    }

    /// Verify token and retrieve user on success
    pub fn verify(&self, token: &str) -> Result<User> {
        let data = decode::<Claims>(token, &self.decoding_key, &self.validation)
            .map_err(|err| Error::TokenValidation(err.to_string()))?;

        Ok(User {
            name: data.claims.sub.to_string(),
            role: data.claims.role,
        })
    }
}
