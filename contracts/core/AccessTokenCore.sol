// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/security/Pausable.sol";
import {ERC1155Burnable} from "@openzeppelin/contracts/token/ERC1155/extensions/ERC1155Burnable.sol";
import {ERC1155, ERC1155Supply} from "@openzeppelin/contracts/token/ERC1155/extensions/ERC1155Supply.sol";
import {IAccessToken} from "../interfaces/IAccessToken.sol";
import {IERC173} from "../interfaces//IERC173.sol";
import {LibArray} from "../libraries/LibArray.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {ShortString, ShortStrings} from "@openzeppelin/contracts/utils/ShortStrings.sol";

abstract contract AccessToken is
    ERC1155Burnable,
    ERC1155Supply,
    Pausable,
    Ownable,
    IAccessToken
{
    using LibArray for *;
    using ShortStrings for *;
    using EnumerableSet for EnumerableSet.AddressSet;

    ShortString internal immutable ADMIN_ROLE =
        ShortStrings.toShortString("ADMIN_ROLE");
    ShortString internal immutable PAUSER_ROLE =
        ShortStrings.toShortString("PAUSER_ROLE");
    ShortString internal immutable DEPLOYER_ROLE =
        ShortStrings.toShortString("DEPLOYER_ROLE");

    uint256 internal constant BLACKLIST_TOKEN =
        uint256(keccak256("BLACKLIST_TOKEN"));

    EnumerableSet.AddressSet internal _registeredProxies;

    modifier onlyRole(ShortString role) virtual {
        _requireRole(role, address(this), msg.sender);
        _;
    }

    function supportsInterface(
        bytes4 interfaceId
    ) public view override returns (bool) {
        return
            super.supportsInterface(interfaceId) ||
            interfaceId == type(IERC173).interfaceId ||
            interfaceId == type(IAccessToken).interfaceId;
    }

    function exec() external payable {}

    function setAccountStatus(
        address account,
        bool shouldBlacklist
    ) external onlyRole(PAUSER_ROLE) returns (bool updated) {
        if (shouldBlacklist) {
            if (!isBlacklisted(account)) {
                updated = true;
                _mint(account, BLACKLIST_TOKEN, 1, "");
            }
        } else {
            if (isBlacklisted(account)) {
                updated = true;
                _burn(account, BLACKLIST_TOKEN, 1);
            }
        }
        if (updated) {
            emit NewAccountStatus(_msgSender(), account, shouldBlacklist);
        }
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function getRoleName(
        address proxy,
        uint256 tokenId
    ) external view returns (string memory) {
        if (!exists(tokenId)) revert ErrTokenUnexists(tokenId);

        ShortString sstr;
        assembly ("memory-safe") {
            sstr := xor(tokenId, proxy)
        }

        return sstr.toString();
    }

    function isBlacklisted(address account) public view returns (bool) {
        return balanceOf(account, BLACKLIST_TOKEN) != 0;
    }

    function getRegisteredProxies()
        public
        view
        returns (address[] memory proxies)
    {
        proxies = _registeredProxies.values();
    }

    function isAuthorized(
        ShortString role,
        address proxy,
        address account
    ) public view returns (bool) {
        if (isBlacklisted(account)) revert ErrBlacklisted(msg.sig, account);
        return
            balanceOf(account, getAccessTokenId(proxy, role)) != 0 ||
            balanceOf(account, getAccessTokenId(address(this), ADMIN_ROLE)) !=
            0;
    }

    function _grantGlobalRoles(
        address admin,
        address[] memory whitelistedDeployers
    ) internal {
        _transferOwnership(admin);

        uint256[] memory amounts = uint256(1).repeat(4);
        address self = address(this);
        uint256 deployerId = getAccessTokenId(self, DEPLOYER_ROLE);
        uint256[] memory ids = LibArray.toUint256s(
            abi.encode(
                deployerId,
                getAccessTokenId(self, ADMIN_ROLE),
                getAccessTokenId(self, PAUSER_ROLE)
            )
        );

        _mintBatch(admin, ids, amounts, "");

        uint256 length = whitelistedDeployers.length;
        for (uint256 i; i < length; ) {
            _mint(whitelistedDeployers[i], deployerId, 1, "");
            unchecked {
                ++i;
            }
        }
    }

    function registerAsProxy() external whenNotPaused {
        address sender = _msgSender();
        if (tx.origin == sender) revert ErrEOAUnallowed(msg.sig);
        _requireRole(DEPLOYER_ROLE, address(this), tx.origin);

        uint256 proxyAdminId = getAccessTokenId(sender, ADMIN_ROLE);
        if (balanceOf(sender, proxyAdminId) != 0) {
            revert ErrAdminRoleAlreadyMintedFor(sender);
        }

        _mint(owner(), proxyAdminId, 1, "");
        _mint(sender, proxyAdminId, 1, "");
        _registeredProxies.add(sender);

        emit ProxyRegistered(sender, tx.origin);
    }

    function mintAccessToken(
        ShortString role,
        address proxy,
        address account
    ) external whenNotPaused {
        _requireRole(ADMIN_ROLE, proxy, _msgSender());
        _mint(account, getAccessTokenId(proxy, role), 1, "");
    }

    function burnAccessToken(
        ShortString role,
        address proxy,
        address account
    ) external whenNotPaused {
        _requireRole(ADMIN_ROLE, proxy, _msgSender());
        _burn(account, getAccessTokenId(proxy, role), 1);
    }

    function getAccessTokenCount(
        address proxy,
        ShortString role
    ) external view returns (uint256) {
        return totalSupply(getAccessTokenId(proxy, role));
    }

    function getAccessTokenId(
        address proxy,
        ShortString role
    ) public pure returns (uint256 id) {
        assembly ("memory-safe") {
            id := xor(proxy, role)
        }
        if (id == BLACKLIST_TOKEN) {
            revert ErrIdCollidedWithBlacklistToken(role, proxy);
        }
    }

    function _beforeTokenTransfer(
        address operator,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) internal virtual override(ERC1155, ERC1155Supply) whenNotPaused {
        uint256 length = ids.length;
        address self = address(this);
        address sender = msg.sender;
        ShortString pauserRole = PAUSER_ROLE;
        uint256 blacklistToken = BLACKLIST_TOKEN;

        for (uint256 i; i < length; ) {
            if (ids[i] == blacklistToken) {
                _requireRole(pauserRole, self, sender);
            }

            unchecked {
                ++i;
            }
        }

        super._beforeTokenTransfer(operator, from, to, ids, amounts, data);
    }

    /// @dev see: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/54a235f8959ecffb1916cf5693ec9bbd695cbf71/contracts/interfaces/draft-IERC6093.sol#L120
    error ERC1155InsufficientBalance(
        address sender,
        uint256 balance,
        uint256 needed,
        uint256 tokenId
    );

    function _requireRole(
        ShortString role,
        address proxy,
        address account
    ) internal view {
        if (!isAuthorized(role, proxy, account)) {
            revert ERC1155InsufficientBalance({
                sender: account,
                balance: 0,
                needed: 1,
                tokenId: getAccessTokenId(proxy, role)
            });
        }
    }
}
