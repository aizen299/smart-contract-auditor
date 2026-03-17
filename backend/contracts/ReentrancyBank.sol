// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ReentrancyBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // ❌ Vulnerable: external call before state update
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Not enough balance");

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");

        balances[msg.sender] -= amount;
    }
}
