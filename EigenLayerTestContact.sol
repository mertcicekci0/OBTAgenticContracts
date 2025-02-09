// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MockEigenLayerValidator {
    mapping(address => bool) private activeValidators;
    mapping(address => uint256) private scores;

    constructor() {
        // Varsayılan olarak bazı hesapları aktif validator yap
        activeValidators[msg.sender] = true;
        scores[msg.sender] = 100;
    }

    function isActiveValidator(address account) external view returns (bool) {
        return activeValidators[account];
    }

    function validatorScore(address account) external view returns (uint256) {
        return scores[account];
    }

    function setValidator(address account, bool isActive, uint256 score) external {
        activeValidators[account] = isActive;
        scores[account] = score;
    }
}
