// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

// Contracts
import {SuperVault} from "./SuperVault.sol";
import {Ownable} from "@solady/auth/Ownable.sol";

// Libraries
import {PredeployAddresses} from "@interop-lib/libraries/PredeployAddresses.sol";
import {Identifier, ICrossL2Inbox} from "@interop-lib/interfaces/ICrossL2Inbox.sol";
import {IL2ToL2CrossDomainMessenger} from "@interop-lib/interfaces/IL2ToL2CrossDomainMessenger.sol";

// Interfaces
import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import {IERC4626} from "@openzeppelin-contracts/interfaces/IERC4626.sol";
import {IERC7802, IERC165} from "@interop-lib/interfaces/IERC7802.sol";

// Utils
import {FixedPointMathLib} from "@solady/utils/FixedPointMathLib.sol";
import {Ownable} from "@solady/auth/Ownable.sol";
import {Errors} from "./Errors.sol";

contract L2NativeSuperVault is Ownable, Errors, SuperVault {
    address immutable _asset;

    /// @dev The L2 to L2 cross domain messenger predeploy to handle message passing
    IL2ToL2CrossDomainMessenger internal messenger =
        IL2ToL2CrossDomainMessenger(PredeployAddresses.L2_TO_L2_CROSS_DOMAIN_MESSENGER);

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                       MODIFIERS                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    /// @dev Modifier to restrict a function to only be a cross-domain callback into this contract
    modifier onlyCrossDomainCallback() {
        if (msg.sender != address(messenger)) {
            revert CallerNotL2ToL2CrossDomainMessenger();
        }
        if (messenger.crossDomainMessageSender() != address(this)) {
            revert InvalidCrossDomainSender();
        }

        _;
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                CONSTRUCTOR                                                //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    constructor(
        address asset_,
        address owner_,
        string memory name_,
        string memory symbol_,
        uint8 decimals_
    ) SuperVault(name_, symbol_, decimals_) {
        _asset = asset_;

        _initializeOwner(owner_);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                   PUBLIC FUNCTIONS                                        //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    function name() public view virtual override returns (string memory) {
        return super.name();
    }

    function symbol() public view virtual override returns (string memory) {
        return super.symbol();
    }

    function decimals() public view virtual override returns (uint8) {
        return super.decimals();
    }

    /// @notice Mints tokens to the specified address
    /// @param to_ The address to mint tokens to
    /// @param amount_ The amount of tokens to mint
    /// @dev Only callable by the contract owner
    function mintTo(address to_, uint256 amount_) external onlyOwner {
        _mint(to_, amount_);
    }

    /// @notice Returns the address of the underlying token used for the Vault for accounting, depositing, and
    /// withdrawing.
    function asset() public view virtual override returns (address) {
        return _asset;
    }
}
