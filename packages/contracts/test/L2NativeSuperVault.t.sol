// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

// Testing utilities
import {Test, console2} from "forge-std/Test.sol";

// Contracts
import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import {ERC20} from "@solady/tokens/ERC20.sol";

// Libraries
import {PredeployAddresses} from "@interop-lib/libraries/PredeployAddresses.sol";
import {Ownable} from "@solady/auth/Ownable.sol";

// Target contract
import {SuperVault} from "../src/SuperVault.sol";
import {L2NativeSuperVault} from "../src/L2NativeSuperVault.sol";
import {SuperchainERC20} from "../src/SuperchainERC20.sol";
import {L2NativeSuperchainERC20} from "../src/L2NativeSuperchainERC20.sol";

contract L2NativeSuperVaultTest is Test {
    address internal constant ZERO_ADDRESS = address(0);
    address internal constant SUPERCHAIN_TOKEN_BRIDGE = PredeployAddresses.SUPERCHAIN_TOKEN_BRIDGE;
    address internal constant MESSENGER = PredeployAddresses.L2_TO_L2_CROSS_DOMAIN_MESSENGER;

    MockSuperToken public superToken;

    address owner;
    address alice;
    address bob;
    address charlie;
    SuperVault superVault;

    function setUp() public {
        owner = makeAddr("owner");
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        charlie = makeAddr("charlie");

        superToken = new MockSuperToken(owner, "Super Token", "SUP", 18);

        vm.prank(owner);
        superVault = new L2NativeSuperVault(address(superToken), address(this), "Super Vault", "vSUP", 18);
        vm.stopPrank();
    }

    /// @notice Helper function to setup a mock and expect a call to it.
    function _mockAndExpect(address _receiver, bytes memory _calldata, bytes memory _returned) internal {
        vm.mockCall(_receiver, _calldata, _returned);
        vm.expectCall(_receiver, _calldata);
    }

    /// @notice Tests the metadata of the token is set correctly.
    function testMetadata() public view {
        assertEq(superToken.name(), "Super Token");
        assertEq(superToken.symbol(), "SUP");
        assertEq(superToken.decimals(), 18);
        // SuperVault
        assertEq(superVault.name(), "Super Vault");
        assertEq(superVault.symbol(), "vSUP");
        assertEq(superVault.decimals(), 18);
    }

    /// @notice Tests that owner can mint tokens to an address.
    function testFuzz_mintTo_succeeds(address _to, uint256 _amount) public {
        vm.expectEmit(true, true, true, true);
        emit IERC20.Transfer(address(0), _to, _amount);

        vm.prank(owner);
        superToken.mintTo(_to, _amount);

        assertEq(superToken.totalSupply(), _amount);
        assertEq(superToken.balanceOf(_to), _amount);
    }

    /// @notice Tests the mintTo function reverts when the caller is not the owner.
    function testFuzz_mintTo_succeeds(address _minter, address _to, uint256 _amount) public {
        vm.assume(_minter != owner);

        // Expect the revert with `Unauthorized` selector
        vm.expectRevert(Ownable.Unauthorized.selector);

        vm.prank(_minter);
        superToken.mintTo(_to, _amount);
    }

    /// @notice Tests that ownership of the token can be renounced.
    function testRenounceOwnership() public {
        vm.expectEmit(true, true, true, true);
        emit Ownable.OwnershipTransferred(owner, address(0));

        vm.prank(owner);
        superToken.renounceOwnership();
        assertEq(superToken.owner(), address(0));
    }

    /// @notice Tests that ownership of the token can be transferred.
    function testFuzz_testTransferOwnership(address _newOwner) public {
        vm.assume(_newOwner != owner);
        vm.assume(_newOwner != ZERO_ADDRESS);

        vm.expectEmit(true, true, true, true);
        emit Ownable.OwnershipTransferred(owner, _newOwner);

        vm.prank(owner);
        superToken.transferOwnership(_newOwner);

        assertEq(superToken.owner(), _newOwner);
    }

    /// @notice Tests that tokens can be transferred using the transfer function.
    function testFuzz_transfer_succeeds(address _sender, uint256 _amount) public {
        vm.assume(_sender != ZERO_ADDRESS);
        vm.assume(_sender != bob);

        vm.prank(owner);
        superToken.mintTo(_sender, _amount);

        vm.expectEmit(true, true, true, true);
        emit IERC20.Transfer(_sender, bob, _amount);

        vm.prank(_sender);
        assertTrue(superToken.transfer(bob, _amount));
        assertEq(superToken.totalSupply(), _amount);

        assertEq(superToken.balanceOf(_sender), 0);
        assertEq(superToken.balanceOf(bob), _amount);
    }

    /// @notice Tests that tokens can be transferred using the transferFrom function.
    function testFuzz_transferFrom_succeeds(address _spender, uint256 _amount) public {
        vm.assume(_spender != ZERO_ADDRESS);
        vm.assume(_spender != bob);
        vm.assume(_spender != alice);

        vm.prank(owner);
        superToken.mintTo(bob, _amount);

        vm.prank(bob);
        // Set allowance to type(uint256).max to comply with Permit2 behavior
        superToken.approve(_spender, type(uint256).max);

        vm.prank(_spender);
        vm.expectEmit(true, true, true, true);
        emit IERC20.Transfer(bob, alice, _amount);
        assertTrue(superToken.transferFrom(bob, alice, _amount));

        assertEq(superToken.balanceOf(bob), 0);
        assertEq(superToken.balanceOf(alice), _amount);
    }

    /// @notice tests that an insufficient balance cannot be transferred.
    function testFuzz_transferInsufficientBalance_reverts(address _to, uint256 _mintAmount, uint256 _sendAmount)
        public
    {
        vm.assume(_mintAmount < type(uint256).max);
        _sendAmount = bound(_sendAmount, _mintAmount + 1, type(uint256).max);

        vm.prank(owner);
        superToken.mintTo(address(this), _mintAmount);

        vm.expectRevert(ERC20.InsufficientBalance.selector);
        superToken.transfer(_to, _sendAmount);
    }

    /// @notice tests that an insufficient allowance cannot be transferred.
    function testFuzz_transferFromInsufficientAllowance_reverts(
        address _to,
        address _from,
        uint256 _approval,
        uint256 _amount
    ) public {
        vm.assume(_from != ZERO_ADDRESS);
        vm.assume(_approval < type(uint256).max);
        _amount = _bound(_amount, _approval + 1, type(uint256).max);

        vm.prank(owner);
        superToken.mintTo(_from, _amount);

        vm.prank(_from);
        superToken.approve(address(this), _approval);

        vm.expectRevert(ERC20.InsufficientAllowance.selector);
        superToken.transferFrom(_from, _to, _amount);
    }


}

contract MockSuperToken is L2NativeSuperchainERC20 {
    constructor(
        address owner_,
        string memory name_,
        string memory symbol_,
        uint8 decimals_
    ) L2NativeSuperchainERC20(owner_, name_, symbol_, decimals_) {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
