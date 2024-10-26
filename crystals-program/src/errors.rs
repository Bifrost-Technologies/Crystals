use anchor_lang::error_code;

#[error_code]
pub enum TerritoryError {
    AlreadyInitialized,
    NotInitialized,
    InvalidPosition
}

#[error_code]
pub enum VampireError {
    AlreadyInitialized,
    NotInitialized,
    AlreadyHunting,
    InvalidLoot
}

#[error_code]
pub enum CraftError {
    AlreadyInitialized,
    NotInitialized,
    InvalidID
}
#[error_code]
pub enum PlayerError {
    AlreadyInitialized,
    NotInitialized,
    NotEnoughCurrencies
}