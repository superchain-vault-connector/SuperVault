//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Contracts
import {ERC20} from "@solady/tokens/ERC20.sol";
import {ERC4626} from "@solady/tokens/ERC4626.sol";
import "./L2NativeSuperchainERC20.sol";

// Libraries
import {PredeployAddresses} from "@interop-lib/libraries/PredeployAddresses.sol";

// Interfaces
import {IERC20} from "@openzeppelin-contracts/interfaces/IERC20.sol";
import {IERC7802, IERC165} from "@interop-lib/interfaces/IERC7802.sol";

// Utils
import {FixedPointMathLib} from "@solady/utils/FixedPointMathLib.sol";
import {SafeTransferLib} from "@solady/utils/SafeTransferLib.sol";

abstract contract TokenVault is IERC7802, ERC4626, L2NativeSuperchainERC20 {
    using FixedPointMathLib for uint256;

    constructor(
        address owner_,
        string memory name_,
        string memory symbol_,
        uint8 decimals_
    ) ERC4626() L2NativeSuperchainERC20(owner_, name_, symbol_, decimals_) {}

    // Override conflicting functions
    function _approve(address owner, address spender, uint256 amount) internal override (ERC20) {
        super._approve(owner, spender, amount);
    }

    function _burn(address account, uint256 amount) internal override (ERC20) {
        super._burn(account, amount);
    }

    function _mint(address account, uint256 amount) internal override (ERC20) {
        super._mint(account, amount);
    }

    function _spendAllowance(address owner, address spender, uint256 amount) internal override (ERC20) {
        super._spendAllowance(owner, spender, amount);
    }

    function _transfer(address from, address to, uint256 amount) internal override (ERC20) {
        super._transfer(from, to, amount);
    }

    function allowance(address owner, address spender) public view override (ERC20) returns (uint256) {
        return super.allowance(owner, spender);
    }

    function approve(address spender, uint256 amount) public override (ERC20) returns (bool) {
        return super.approve(spender, amount);
    }

    function balanceOf(
        address account
    ) public view override (ERC20) returns (uint256) {
        return super.balanceOf(account);
    }

    function decimals() public view virtual override (ERC4626, L2NativeSuperchainERC20) returns (uint8) {
        return super.decimals();
    }

    function name() public view override (ERC20, L2NativeSuperchainERC20) returns (string memory) {
        return super.name();
    }

    function symbol() public view override (ERC20, L2NativeSuperchainERC20) returns (string memory) {
        return super.symbol();
    }

    function totalSupply() public view override (ERC20) returns (uint256) {
        return super.totalSupply();
    }

    function transfer(address to, uint256 amount) public override (ERC20) returns (bool) {
        return super.transfer(to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) public override (ERC20) returns (bool) {
        return super.transferFrom(from, to, amount);
    }

    /// @inheritdoc IERC165
    function supportsInterface(
        bytes4 _interfaceId
    ) public view virtual override (IERC165, SuperchainERC20) returns (bool) {
        return _interfaceId == type(IERC7802).interfaceId || _interfaceId == type(IERC20).interfaceId
            || _interfaceId == type(IERC165).interfaceId;
    }
}
