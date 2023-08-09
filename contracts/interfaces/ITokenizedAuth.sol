// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {IAccessToken} from "./IAccessToken.sol";

interface ITokenizedAuth {
    error ErrUnauthorized(bytes4 msgSig);

    event NewAccessToken(
        address indexed operator,
        IAccessToken indexed prevToken,
        IAccessToken indexed newToken
    );

    function setAccessToken(IAccessToken accessToken) external;

    function getAccessToken() external view returns (IAccessToken);
}
