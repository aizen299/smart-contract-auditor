// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Arbitrum-specific interface
interface ArbSys {
    function arbBlockNumber() external view returns (uint256);
}

interface IL2CrossDomainMessenger {
    function xDomainMessageSender() external view returns (address);
}

/**
 * @title ArbitrumVault
 * @notice Test contract with Arbitrum L2 identifiers + real vulnerabilities
 * Expected: CRITICAL reentrancy, HIGH access control + L2 Arbitrum findings
 */
contract ArbitrumVault {
    ArbSys constant arbsys = ArbSys(address(100));

    mapping(address => uint256) public balances;
    address public owner;
    address public l1Contract;

    constructor(address _l1Contract) {
        owner = msg.sender;
        l1Contract = _l1Contract;
    }

    // VULNERABILITY: No check that msg.sender is the bridge contract
    // L2 finding: Unvalidated Bridge Message Sender
    function onL1Deposit(address user, uint256 amount) external {
        balances[user] += amount;
    }

    // VULNERABILITY: Reentrancy — state updated after external call
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
        balances[msg.sender] -= amount;
    }

    // VULNERABILITY: Uses block.number — behaves differently on Arbitrum
    // L2 finding: L2 Block Number Assumption
    function isExpired(uint256 expiryBlock) external view returns (bool) {
        return block.number > expiryBlock;
    }

    // VULNERABILITY: No access control
    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    function getL2Block() external view returns (uint256) {
        return arbsys.arbBlockNumber();
    }

    receive() external payable {}
}
