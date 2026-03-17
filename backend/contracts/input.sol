// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * VULNERABLE CONTRACT - FOR TESTING PURPOSES ONLY
 * Contains: Reentrancy, Integer Overflow, Access Control, TX Origin, Unchecked Call
 * DO NOT DEPLOY ON MAINNET
 */
contract VulnerableBank {

    mapping(address => uint256) public balances;
    address public owner;
    bool public locked;

    constructor() {
        owner = msg.sender;
    }

    // ================================================
    // VULNERABILITY 1: Reentrancy Attack
    // Fix: Use checks-effects-interactions pattern
    // ================================================
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // BUG: External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount; // State updated AFTER call
    }

    // ================================================
    // VULNERABILITY 2: Integer Overflow (pre-0.8 style)
    // Simulated with unchecked block
    // ================================================
    function unsafeAdd(uint256 a, uint256 b) public pure returns (uint256) {
        unchecked {
            return a + b; // Can overflow
        }
    }

    function unsafeSubtract(uint256 a, uint256 b) public pure returns (uint256) {
        unchecked {
            return a - b; // Can underflow
        }
    }

    // ================================================
    // VULNERABILITY 3: tx.origin Authentication
    // Fix: Use msg.sender instead
    // ================================================
    function txOriginTransfer(address payable recipient, uint256 amount) public {
        require(tx.origin == owner, "Not owner"); // BUG: tx.origin is exploitable
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
    }

    // ================================================
    // VULNERABILITY 4: Missing Access Control
    // Fix: Add onlyOwner modifier
    // ================================================
    function setOwner(address newOwner) public {
        // BUG: Anyone can call this
        owner = newOwner;
    }

    // ================================================
    // VULNERABILITY 5: Unchecked Return Value
    // Fix: Check the return value of send/call
    // ================================================
    function unsafeSend(address payable recipient, uint256 amount) public {
        recipient.send(amount); // BUG: Return value ignored
    }

    // ================================================
    // VULNERABILITY 6: Unprotected Selfdestruct
    // Fix: Add access control
    // ================================================
    function destroy() public {
        // BUG: Anyone can destroy the contract
        selfdestruct(payable(msg.sender));
    }

    // ================================================
    // VULNERABILITY 7: Timestamp Dependence
    // Fix: Avoid block.timestamp for randomness/logic
    // ================================================
    function isWinner() public view returns (bool) {
        return (block.timestamp % 2 == 0); // BUG: Miners can manipulate
    }

    // ================================================
    // VULNERABILITY 8: Delegatecall to Untrusted Address
    // Fix: Never delegatecall to user-supplied addresses
    // ================================================
    function proxyCall(address target, bytes memory data) public {
        // BUG: Delegatecall to arbitrary address
        (bool success, ) = target.delegatecall(data);
        require(success, "Delegatecall failed");
    }

    // ================================================
    // VULNERABILITY 9: Hardcoded Sensitive Value
    // Fix: Use a secure auth mechanism
    // ================================================
    function adminLogin(uint256 pin) public view returns (bool) {
        return pin == 1234; // BUG: Hardcoded secret visible on-chain
    }

    // ================================================
    // VULNERABILITY 10: Denial of Service via Gas Limit
    // Fix: Use pull-payment pattern
    // ================================================
    address[] public investors;

    function addInvestor(address investor) public {
        investors.push(investor);
    }

    function distributeRewards() public payable {
        // BUG: Loop can run out of gas if investors array is large
        for (uint256 i = 0; i < investors.length; i++) {
            payable(investors[i]).transfer(msg.value / investors.length);
        }
    }

    // Deposit function
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    receive() external payable {}
}
