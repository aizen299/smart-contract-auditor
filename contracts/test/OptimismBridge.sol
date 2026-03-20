// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IL2CrossDomainMessenger {
    function xDomainMessageSender() external view returns (address);
}

/**
 * @title OptimismBridge
 * @notice Test contract with Optimism L2 identifiers + real vulnerabilities
 * Expected: CRITICAL reentrancy + HIGH tx.origin + L2 Optimism findings
 */
contract OptimismBridge {
    IL2CrossDomainMessenger public messenger;
    address public trustedL1Contract;
    mapping(address => uint256) public deposits;

    event Deposited(address indexed user, uint256 amount);

    constructor(address _messenger, address _l1Contract) {
        messenger = IL2CrossDomainMessenger(_messenger);
        trustedL1Contract = _l1Contract;
    }

    // VULNERABILITY: Does not verify xDomainMessageSender
    // L2 finding: Unvalidated Bridge Message Sender
    function onDeposit(address user, uint256 amount) external {
        deposits[user] += amount;
        emit Deposited(user, amount);
    }

    // VULNERABILITY: Uses block.timestamp — sequencer controlled on Optimism
    // L2 finding: L2 Timestamp Assumption
    function isClaimable(uint256 unlockTime) external view returns (bool) {
        return block.timestamp >= unlockTime;
    }

    // VULNERABILITY: Unchecked low level call
    function sweep(address token, address to, uint256 amount) external {
        token.call(
            abi.encodeWithSignature("transfer(address,uint256)", to, amount)
        );
    }

    // VULNERABILITY: tx.origin authentication
    function adminAction() external {
        require(tx.origin == address(0x1234), "Not admin");
    }

    // VULNERABILITY: Reentrancy
    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        deposits[msg.sender] -= amount;
    }

    receive() external payable {}
}
