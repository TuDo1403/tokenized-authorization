// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {LibErrorHandler} from "../libraries/LibErrorHandler.sol";

contract RoleBasedAccount is Initializable, Ownable {
    using LibErrorHandler for *;

    error ErrNotInitialized();

    address internal immutable DEPLOYER;
    address internal _proxy;

    fallback() external payable onlyOwner {
        if (_proxy == address(0)) revert ErrNotInitialized();

        (bool success, bytes memory returnData) = _proxy.call{value: msg.value}(msg.data);
        success.handleRevert(bytes4(msg.data[:4]), returnData);

        assembly ("memory-safe") {
            return(add(returnData, 0x20), mload(returnData))
        }
    }

    receive() external payable {
        revert();
    }

    constructor() payable {
        DEPLOYER = _msgSender();
        _disableInitializers();
    }

    /// @dev see: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/9e3f4d60c581010c4a3979480e07cc7752f124cc/contracts/access/Ownable.sol#L26C5-L26C55
    error OwnableUnauthorizedAccount(address account);

    function initialize(address proxy) external initializer {
        address sender = _msgSender();
        if (sender != DEPLOYER) revert OwnableUnauthorizedAccount(sender);

        _transferOwnership(sender);
        _proxy = proxy;
    }
}
