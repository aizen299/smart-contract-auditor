// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Generic L2 bridge interface
interface IL1Bridge {
    function sendMessage(address target, bytes calldata data) external payable;
}

interface IL2Bridge {
    function finalizeDeposit(address from, address to, uint256 amount) external;
}

interface CrossChainEnabled {
    function crossChainSender() external view returns (address);
}

/**
 * @title CrossChainStaking
 * @notice Test contract with generic L2 bridge identifiers + vulnerabilities
 * Expected: CRITICAL reentrancy + HIGH findings + generic L2 findings
 */
contract CrossChainStaking {
    IL2Bridge public bridge;
    mapping(address => uint256) public staked;
    mapping(address => uint256) public rewards;
    uint256 public rewardRate = 100;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    constructor(address _bridge) {
        bridge = IL2Bridge(_bridge);
        owner = msg.sender;
    }

    // VULNERABILITY: No chain ID in signature — replay attack possible
    // L2 finding: Cross-Chain Replay Attack
    function claimWithSignature(
        uint256 amount,
        bytes memory signature
    ) external {
        // Missing chain ID check in signature verification
        bytes32 hash = keccak256(abi.encodePacked(msg.sender, amount));
        // ... signature verification without chainid
        rewards[msg.sender] += amount;
    }

    // VULNERABILITY: Reentrancy
    function unstake(uint256 amount) external {
        require(staked[msg.sender] >= amount);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        staked[msg.sender] -= amount;
    }

    // VULNERABILITY: Owner can change reward rate with no timelock
    // No event emitted
    function setRewardRate(uint256 rate) external onlyOwner {
        rewardRate = rate;
    }

    // VULNERABILITY: block.timestamp used for reward calculation
    // L2 finding: L2 Timestamp Assumption
    function pendingReward(address user) external view returns (uint256) {
        return staked[user] * rewardRate * block.timestamp / 1e18;
    }

    receive() external payable {
        staked[msg.sender] += msg.value;
    }
}
