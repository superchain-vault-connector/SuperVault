// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

// Testing utilities
import {Test, console2} from "forge-std/Test.sol";

// Contracts
import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import {ERC20} from "@openzeppelin-contracts/token/ERC20/ERC20.sol";

// Libraries
import {PredeployAddresses} from "@interop-lib/libraries/PredeployAddresses.sol";

// Target contract
import {SuperVault} from "../src/SuperVault.sol";
import {L2NativeSuperVault} from "../src/L2NativeSuperVault.sol";
import {SuperchainERC20} from "../src/SuperchainERC20.sol";
import {L2NativeSuperchainERC20} from "../src/L2NativeSuperchainERC20.sol";

contract SuperVaultTest is Test {
    address internal constant ZERO_ADDRESS = address(0);
    address internal constant SUPERCHAIN_TOKEN_BRIDGE = PredeployAddresses.SUPERCHAIN_TOKEN_BRIDGE;
    address internal constant MESSENGER = PredeployAddresses.L2_TO_L2_CROSS_DOMAIN_MESSENGER;

    MockSuperToken public superToken;

    address owner;
    address alice;
    address bob;
    address charlie;
    SuperVault superVault;
    MockERC20 depositToken;

    function setUp() public {
        owner = makeAddr("owner");
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        charlie = makeAddr("charlie");

        superToken = new MockSuperToken(owner, "Super Token", "SUP", 18);

        vm.prank(owner);
        superToken.mint(alice, 10 ether);
        superToken.mint(bob, 10 ether);
        superToken.mint(owner, 12 ether);
        superVault = new L2NativeSuperVault(address(superToken), address(this), "Super Vault", "vSUP", 18);
        vm.stopPrank();
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

    function setup_mint() public {
        vm.startPrank(alice);
        superToken.approve(address(superVault), 1 ether);
        superVault.mint(1 ether, alice);
        assertEq(superVault.balanceOf(alice), 1 ether);
        assertEq(superToken.balanceOf(address(superVault)), 1 ether);
        assertEq(superToken.balanceOf(alice), 9 ether);
        vm.stopPrank();
    }

    function test_deposit() public {
        vm.startPrank(alice);
        superToken.approve(address(superVault), 1 ether);
        superVault.deposit(1 ether, alice);
        assertEq(superVault.balanceOf(alice), 1 ether);
        assertEq(superToken.balanceOf(address(superVault)), 1 ether);
        vm.stopPrank();
    }

    function test_withdraw() public {
        setup_mint();
        vm.startPrank(alice);
        superVault.withdraw(1 ether, alice, alice);
        assertEq(superVault.balanceOf(alice), 0);
        assertEq(superToken.balanceOf(address(superVault)), 0);
        assertEq(superToken.balanceOf(alice), 10 ether);
        vm.stopPrank();
    }

    function test_redeem() public {
        setup_mint();
        vm.startPrank(alice);
        superVault.redeem(1 ether, alice, alice);
        assertEq(superVault.balanceOf(alice), 0);
        assertEq(superToken.balanceOf(address(superVault)), 0);
        assertEq(superToken.balanceOf(alice), 10 ether);
        vm.stopPrank();
    }

    function setup_shareholders() public {
        vm.startPrank(owner);
        superToken.approve(address(superVault), 10 ether);
        superVault.deposit(10 ether, owner);
        vm.stopPrank();
        vm.startPrank(alice);
        superToken.approve(address(superVault), 10 ether);
        superVault.deposit(10 ether, alice);
        vm.stopPrank();
        assertEq(superVault.balanceOf(owner), 10 ether);
        assertEq(superVault.balanceOf(alice), 10 ether);
    }

    // function test_profitSharing() public {
    //     setup_shareholders();
    //     vm.startPrank(owner);
    //     depositToken.approve(address(superVault), 2 ether);
    //     superVault.shareProfits(2 ether);
    //     vm.stopPrank();
    //     assertEq(depositToken.balanceOf(address(superVault)), 22 ether);
    //     uint256 owner_share = superVault.previewRedeem(10 ether);
    //     assertEq(owner_share, 11 ether);
    // }
}

contract MockERC20 is ERC20 {
    constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
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
