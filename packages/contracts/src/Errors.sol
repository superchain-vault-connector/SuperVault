// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

/// @title Errors
/// @author Adapole, Adg0
/// @notice This contract implements the error messages for Superchain ERC4626 Vault (SuperVault).
contract Errors {
    /// @notice Thrown when the caller is not the L2ToL2CrossDomainMessenger.
    error CallerNotL2ToL2CrossDomainMessenger();

    /// @notice Thrown when the cross-domain sender is not this contract's address on another chain.
    error InvalidCrossDomainSender();

    /// @notice Thrown when attempting to use a token that does not implement the ERC7802 interface.
    error InvalidERC7802();
}
