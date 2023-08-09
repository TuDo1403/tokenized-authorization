// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC165, IERC1155} from "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {IAccessControl, IAccessControlEnumerable} from "@openzeppelin/contracts/access/IAccessControlEnumerable.sol";
import {IAccessToken, ITokenizedAuth} from "../interfaces/ITokenizedAuth.sol";
import {IERC165, IERC173} from "../interfaces/IERC173.sol";
import {ShortString} from "@openzeppelin/contracts/utils/ShortStrings.sol";

abstract contract TokenizedAuthCore is
    Ownable,
    IAccessControl,
    ITokenizedAuth,
    IERC1155Receiver
{
    IAccessToken internal _accessToken;

    modifier onlyRole(bytes32 role) virtual {
        _requireRole(role, msg.sender);
        _;
    }

    modifier onlyAccessToken() virtual {
        _requireAccessToken();
        _;
    }

    function setAccessToken(
        IAccessToken accessToken
    ) external virtual onlyOwner {
        _setAccessToken(accessToken);
    }

    function getAccessToken() external view virtual returns (IAccessToken) {
        return _accessToken;
    }

    function hasRole(
        address account,
        bytes32 role
    ) public view virtual returns (bool) {
        IAccessToken accessToken = _accessToken;
        return
            (address(accessToken) != address(0) &&
                accessToken.isAuthorized(
                    ShortString.wrap(role),
                    address(this),
                    account
                )) || account == owner();
    }

    function onERC1155Received(
        address /* operator */,
        address /* from */,
        uint256 /* id */,
        uint256 /* value */,
        bytes calldata /* data */
    ) external view virtual onlyAccessToken returns (bytes4) {
        return IERC1155Receiver.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(
        address /* operator */,
        address /* from */,
        uint256[] calldata /* ids */,
        uint256[] calldata /* values */,
        bytes calldata /* data */
    ) external view virtual onlyAccessToken returns (bytes4) {
        return IERC1155Receiver.onERC1155BatchReceived.selector;
    }

    function getRoleMemberCount(
        bytes32 role
    ) public view virtual returns (uint256) {
        return
            _accessToken.getAccessTokenCount(
                address(this),
                ShortString.wrap(role)
            );
    }

    function supportsInterface(
        bytes4 interfaceId
    ) public pure virtual returns (bool) {
        return
            interfaceId == type(IERC165).interfaceId ||
            interfaceId == type(IERC173).interfaceId ||
            interfaceId == type(ITokenizedAuth).interfaceId ||
            interfaceId == type(IAccessControl).interfaceId ||
            interfaceId == type(IERC1155Receiver).interfaceId;
    }

    function _setAccessToken(IAccessToken accessToken) internal virtual {
        emit NewAccessToken(msg.sender, _accessToken, accessToken);
        _accessToken = accessToken;
    }

    function _registerAsProxy() internal virtual {
        _accessToken.registerAsProxy();
    }

    function _grantRole(bytes32 role, address account) internal virtual {
        _accessToken.mintAccessToken(ShortString.wrap(role), account);
    }

    function _revokeRole(bytes32 role, address account) internal virtual {
        _accessToken.burnAccessToken(ShortString.wrap(role), account);
    }

    function _requireAccessToken() internal view virtual {
        if (msg.sender != address(_accessToken)) {
            revert ErrUnauthorized(msg.sig);
        }
    }

    /// @dev see: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/48b860124c36d5012ca8eee925458fb0c6c008c0/contracts/access/IAccessControl.sol#L13
    error AccessControlUnauthorizedAccount(address account, bytes32 role);

    function _requireRole(bytes32 role, address account) internal view virtual {
        if (!hasRole(account, role)) {
            revert AccessControlUnauthorizedAccount(account, role);
        }
    }
}
