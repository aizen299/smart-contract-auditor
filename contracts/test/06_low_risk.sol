// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title  LowRiskRegistry
 * @notice A simple registry with genuine LOW findings Slither detects.
 *
 * Expected findings:
 *  - LOW: events-access — setOwner emits no event
 *  - LOW: events-maths  — setFee emits no event
 *  - LOW: missing-zero-check — register() accepts zero address
 *  - LOW: incorrect-equality — uses == on uint256
 */
contract LowRiskRegistry {

    address public owner;
    uint256 public fee;

    mapping(address => string) public registry;
    address[] public registered;

    event Registered(address indexed addr, string name);

    constructor() {
        owner = msg.sender;
        fee = 0;
    }

    // missing-zero-check: addr could be address(0)
    function register(address addr, string calldata name) external {
        require(msg.sender == owner, "Not owner");
        registry[addr] = name;
        registered.push(addr);
        emit Registered(addr, name);
    }

    function lookup(address addr) external view returns (string memory) {
        return registry[addr];
    }

    function count() external view returns (uint256) {
        return registered.length;
    }

    // incorrect-equality: strict equality on uint256
    function isFree() external view returns (bool) {
        return fee == 0;
    }

    // events-maths: changes fee with no event
    function setFee(uint256 newFee) external {
        require(msg.sender == owner, "Not owner");
        fee = newFee;
    }

    // events-access: transfers ownership with no event
    function setOwner(address newOwner) external {
        require(msg.sender == owner, "Not owner");
        require(newOwner != address(0), "Zero address");
        owner = newOwner;
    }
}
