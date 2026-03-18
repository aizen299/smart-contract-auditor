// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title  HighRiskVault
 * @notice Intentionally vulnerable contract — should return HIGH risk score
 *         with multiple CRITICAL and HIGH findings
 */
contract HighRiskVault {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // CRITICAL: Reentrancy — state updated AFTER external call
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount; // too late — reentrancy possible
    }

    // HIGH: Arbitrary ETH send to user-controlled address
    function sendTo(address payable to, uint256 amount) public {
        require(msg.sender == owner);
        to.transfer(amount);
    }

    // HIGH: tx.origin authentication
    function adminWithdraw() public {
        require(tx.origin == owner, "Not owner");
        payable(owner).transfer(address(this).balance);
    }

    // HIGH: Unchecked low-level call
    function callExternal(address target, bytes memory data) public {
        target.call(data);
    }

    // MEDIUM: Block timestamp used for logic
    function isExpired(uint256 deadline) public view returns (bool) {
        return block.timestamp > deadline;
    }

    // LOW: Missing zero address check
    function setOwner(address newOwner) public {
        require(msg.sender == owner);
        owner = newOwner;
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}
