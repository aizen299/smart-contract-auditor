// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title  MediumRiskToken
 * @notice A basic ERC-20-like token with some medium/low risk issues
 *         Should return MEDIUM risk score (30-50 range)
 */
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract MediumRiskToken {
    string public name = "MediumRiskToken";
    string public symbol = "MRT";
    uint256 public totalSupply;
    address public owner;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // LOW: No event emitted on ownership transfer
    // LOW: Single-step ownership transfer
    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "Not owner");
        owner = newOwner;
    }

    // MEDIUM: No upper bound on mint amount — owner can mint unlimited tokens
    function mint(address to, uint256 amount) external {
        require(msg.sender == owner, "Not owner");
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    // MEDIUM: block.timestamp used for vesting logic
    uint256 public vestingStart;
    function isVested() public view returns (bool) {
        return block.timestamp >= vestingStart + 365 days;
    }

    // LOW: Missing zero address check on transfer
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "Not allowed");
        require(balanceOf[from] >= amount, "Insufficient");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    constructor() {
        owner = msg.sender;
        vestingStart = block.timestamp;
    }
}
