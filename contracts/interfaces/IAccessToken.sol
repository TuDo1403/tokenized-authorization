// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {ShortString} from "@openzeppelin/contracts/utils/ShortStrings.sol";

interface IAccessToken {
    error ErrLengthMismatch();
    error ErrAccountNotCreated();
    error ErrEOAUnallowed(bytes4 msgSig);
    error ErrTokenUnexists(uint256 tokenId);
    error ErrAdminRoleAlreadyMintedFor(address proxy);
    error ErrBlacklisted(bytes4 msgSig, address account);
    error ErrIdCollision(ShortString role, address proxy);

    struct RoleInfo {
        bytes32 role;
        address[] members;
    }

    event NewAccountStatus(address indexed operator, address indexed account, bool indexed status);

    event ProxyRegistered(address indexed originCaller, address indexed proxy);

    function registerAsProxy() external;

    function exec(bytes32 role, address to, bytes calldata params) external payable returns (bytes memory returnData);

    function createRoleBasedAccounts(address[] calldata proxies, RoleInfo[] calldata roleInfos) external;

    function getRoleBasedAccount(bytes32 role, address proxy) external view returns (address);

    function mintAccessToken(ShortString role, address account) external;

    function burnAccessToken(ShortString role, address account) external;

    function pause() external;

    function unpause() external;

    function ADMIN_ROLE() external view returns (ShortString);

    function PAUSER_ROLE() external view returns (ShortString);

    function DEPLOYER_ROLE() external view returns (ShortString);

    function BLACKLIST_TOKEN() external view returns (uint256);

    function isBlacklisted(address account) external view returns (bool);

    function isAuthorized(ShortString role, address proxy, address account) external view returns (bool);

    function getAccessTokenId(address proxy, ShortString role) external view returns (uint256 id);

    function getAccessTokenCount(address proxy, ShortString role) external view returns (uint256);

    function setAccountStatus(address account, bool shouldBlacklist) external returns (bool updated);
}
