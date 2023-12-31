// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Pausable} from "@openzeppelin/contracts/security/Pausable.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {ERC1155Burnable} from "@openzeppelin/contracts/token/ERC1155/extensions/ERC1155Burnable.sol";
import {ERC1155, ERC1155Supply} from "@openzeppelin/contracts/token/ERC1155/extensions/ERC1155Supply.sol";
import {ERC1155URIStorage} from "@openzeppelin/contracts/token/ERC1155/extensions/ERC1155URIStorage.sol";
import {IAccessToken} from "../interfaces/IAccessToken.sol";
import {IERC173} from "../interfaces//IERC173.sol";
import {LibArray} from "../libraries/LibArray.sol";
import {LibErrorHandler} from "../libraries/LibErrorHandler.sol";
import {IRoleBasedProxy, RoleBasedProxy} from "../utils/RoleBasedProxy.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {ShortString, ShortStrings} from "@openzeppelin/contracts/utils/ShortStrings.sol";

abstract contract AccessToken is
    Initializable,
    Pausable,
    ERC1155Supply,
    ERC1155Burnable,
    ERC1155URIStorage,
    IAccessToken
{
    using Clones for *;
    using Strings for *;
    using LibArray for *;
    using ShortStrings for *;
    using EnumerableSet for *;
    using LibErrorHandler for *;

    ShortString public immutable ADMIN_ROLE = ShortStrings.toShortString("ADMIN_ROLE");
    ShortString public immutable DEPLOYER_ROLE = ShortStrings.toShortString("DEPLOYER_ROLE");

    address internal _admin;
    address internal _roleBasedAccountImpl;
    EnumerableSet.AddressSet internal _registeredProxies;
    mapping(address => EnumerableSet.Bytes32Set) internal _proxyRoles;
    mapping(address => mapping(ShortString => EnumerableSet.AddressSet)) internal _roleMembers;

    modifier onlyRole(ShortString role) virtual {
        _requireRole(role, address(this), msg.sender);
        _;
    }

    function uri(uint256 tokenId) public view virtual override(ERC1155, ERC1155URIStorage) returns (string memory) {
        return super.uri(tokenId);
    }

    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return
            super.supportsInterface(interfaceId) ||
            interfaceId == type(IERC173).interfaceId ||
            interfaceId == type(IAccessToken).interfaceId;
    }

    function createRoleBasedAccounts(
        address[] calldata proxies,
        RoleInfo[] calldata roleInfos
    ) external virtual onlyRole(ADMIN_ROLE) {
        uint256 length = proxies.length;
        if (length != roleInfos.length) revert ErrLengthMismatch();

        bytes32 salt;
        address deployed;
        uint256 memberLength;
        address roleBasedAccountImpl = _roleBasedAccountImpl;

        for (uint256 i; i < length; ) {
            if (proxies[i] == address(this)) revert ErrInvalidArgument();

            salt = keccak256(abi.encode(roleInfos[i].role, proxies[i]));
            deployed = roleBasedAccountImpl.cloneDeterministic(salt);
            IRoleBasedProxy(deployed).initialize(proxies[i]);

            memberLength = roleInfos[i].members.length;
            for (uint256 j; j < memberLength; ) {
                _mintAccessToken(ShortString.wrap(roleInfos[i].role), proxies[i], roleInfos[i].members[j]);

                unchecked {
                    ++j;
                }
            }

            unchecked {
                ++i;
            }
        }
    }

    function getRoleBasedAccount(bytes32 role, address proxy) public view virtual returns (address) {
        return Clones.predictDeterministicAddress(_roleBasedAccountImpl, keccak256(abi.encode(role, proxy)));
    }

    function exec(
        bytes32 role,
        address to,
        bytes calldata params
    ) external payable virtual returns (bytes memory returnData) {
        _requireRole(ShortString.wrap(role), to, msg.sender);

        address roleBasedAccount = getRoleBasedAccount(role, to);
        if (roleBasedAccount.code.length == 0) revert ErrAccountNotCreated();

        bool success;
        (success, returnData) = roleBasedAccount.call{value: msg.value}(params);
        success.handleRevert(bytes4(params[:4]), returnData);
    }

    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    function getRoleName(address proxy, uint256 tokenId) external view virtual returns (string memory) {
        if (!exists(tokenId)) revert ErrTokenUnexists(tokenId);

        ShortString sstr;
        assembly ("memory-safe") {
            sstr := xor(tokenId, proxy)
        }

        return sstr.toString();
    }

    function getRegisteredProxies() public view returns (address[] memory proxies) {
        proxies = _registeredProxies.values();
    }

    function isAuthorized(ShortString role, address proxy, address account) public view virtual returns (bool) {
        return
            balanceOf(account, getAccessTokenId(proxy, role)) != 0 ||
            balanceOf(account, getAccessTokenId(address(this), ADMIN_ROLE)) != 0;
    }

    function _setupAdminRoles(address admin, address[] memory whitelistedDeployers) internal virtual onlyInitializing {
        _admin = admin;
        _roleBasedAccountImpl = address(new RoleBasedProxy());

        address self = address(this);
        uint256 deployerId = getAccessTokenId(self, DEPLOYER_ROLE);
        uint256[] memory ids = LibArray.toUint256s(abi.encode(deployerId, getAccessTokenId(self, ADMIN_ROLE)));
        uint256[] memory amounts = uint256(1).repeat(ids.length);

        _mintBatch(admin, ids, amounts, "");

        uint256 length = whitelistedDeployers.length;
        for (uint256 i; i < length; ) {
            _mint(whitelistedDeployers[i], deployerId, 1, "");
            unchecked {
                ++i;
            }
        }
    }

    function registerAsProxy() external virtual whenNotPaused {
        address sender = _msgSender();
        if (tx.origin == sender) revert ErrEOAUnallowed(msg.sig);
        _requireRole(DEPLOYER_ROLE, address(this), tx.origin);

        ShortString adminRole = ADMIN_ROLE;
        uint256 proxyAdminId = getAccessTokenId(sender, adminRole);
        if (balanceOf(sender, proxyAdminId) != 0) {
            revert ErrAdminRoleAlreadyMintedFor(sender);
        }

        _mintAccessToken(adminRole, sender, _admin);
        _mintAccessToken(adminRole, sender, sender);
        _mintAccessToken(adminRole, sender, IERC173(sender).owner());

        _registeredProxies.add(sender);

        emit ProxyRegistered(sender, tx.origin);
    }

    function mintAccessToken(ShortString role, address proxy, address account) external virtual whenNotPaused {
        _requireRole(ADMIN_ROLE, proxy, _msgSender());
        _mintAccessToken(role, proxy, account);
    }

    function burnAccessToken(ShortString role, address proxy, address account) external virtual whenNotPaused {
        _requireRole(ADMIN_ROLE, proxy, _msgSender());
        _burnAccessToken(role, proxy, account);
    }

    function getAccessTokenCount(address proxy, ShortString role) external view returns (uint256) {
        return totalSupply(getAccessTokenId(proxy, role));
    }

    function getAccessTokenId(address proxy, ShortString role) public view virtual returns (uint256 id) {
        assembly ("memory-safe") {
            id := xor(proxy, role)
        }

        address self = address(this);
        if (self != proxy) {
            if (id == getAccessTokenId(self, ADMIN_ROLE) || id == getAccessTokenId(self, DEPLOYER_ROLE)) {
                revert ErrIdCollision(role, proxy);
            }
        }
    }

    function _mintAccessToken(ShortString role, address proxy, address account) internal virtual {
        uint256 roleId = getAccessTokenId(proxy, role);

        _mint(account, roleId, 1, "");
        _setURI(roleId, string(abi.encodePacked(proxy.toHexString(), "@", role.toString())));
        _roleMembers[proxy][role].add(account);
        _proxyRoles[proxy].add(ShortString.unwrap(role));
    }

    function _burnAccessToken(ShortString role, address proxy, address account) internal virtual {
        uint256 roleId = getAccessTokenId(proxy, role);

        _burn(account, roleId, 1);
        _setURI(roleId, "");

        _roleMembers[proxy][role].remove(account);
        _proxyRoles[proxy].remove(ShortString.unwrap(role));
    }

    function _beforeTokenTransfer(
        address operator,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) internal virtual override(ERC1155, ERC1155Supply) whenNotPaused {
        if (_msgSender() == from) revert ErrDirectTransferUnallowed(msg.sig, from, operator);

        super._beforeTokenTransfer(operator, from, to, ids, amounts, data);
    }

    /// @dev see: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/54a235f8959ecffb1916cf5693ec9bbd695cbf71/contracts/interfaces/draft-IERC6093.sol#L120
    error ERC1155InsufficientBalance(address sender, uint256 balance, uint256 needed, uint256 tokenId);

    function _requireRole(ShortString role, address proxy, address account) internal view {
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
