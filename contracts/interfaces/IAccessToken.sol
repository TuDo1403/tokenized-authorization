// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {ShortString} from "@openzeppelin/contracts/utils/ShortStrings.sol";

interface IAccessToken {
    error ErrEOAUnallowed(bytes4 msgSig);
    error ErrTokenUnexists(uint256 tokenId);
    error ErrAdminRoleAlreadyMintedFor(address proxy);
    error ErrBlacklisted(bytes4 msgSig, address account);
    error ErrIdCollidedWithBlacklistToken(ShortString role, address proxy);

    event NewAccountStatus(
        address indexed operator,
        address indexed account,
        bool indexed status
    );

    event ProxyRegistered(address indexed originCaller, address indexed proxy);

    function isBlacklisted(address account) external view returns (bool);

    function registerAsProxy() external;

    function mintAccessToken(ShortString role, address account) external;

    function burnAccessToken(ShortString role, address account) external;

    function pause() external;

    function unpause() external;

    function isAuthorized(
        ShortString role,
        address proxy,
        address account
    ) external view returns (bool);

    function getAccessTokenId(
        address proxy,
        ShortString role
    ) external pure returns (uint256 id);

    function getAccessTokenCount(
        address proxy,
        ShortString role
    ) external view returns (uint256);

    function setAccountStatus(
        address account,
        bool shouldBlacklist
    ) external returns (bool updated);
}
