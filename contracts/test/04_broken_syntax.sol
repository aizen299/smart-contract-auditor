// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title  BrokenContract
 * @notice Intentional syntax error — should return 422 error
 *         "Could not analyse contract. It may contain syntax errors..."
 */
contract BrokenContract {
    uint256 public value;

    // Missing closing parenthesis — syntax error
    function setValue(uint256 newValue {
        value = newValue;
    }

    function getValue() public view returns (uint256) {
        return value
    }
}
