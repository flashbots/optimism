// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { ERC721 } from "@openzeppelin/contracts/token/ERC721/ERC721.sol";

/**
 * @title RetroReceiver
 * @notice RetroReceiver is a minimal contract for receiving funds, meant to be deployed at the
 * same address on every chain that supports EIP-2470.
 */
contract RetroReceiver is Ownable, Initializable {
    /**
     * @param _owner Address to initially own the contract.
     */
    constructor(address _owner) {
        initialize(_owner);
    }

    /**
     * Make sure we can receive ETH.
     */
    receive() external payable {}

    /**
     * Initializes the contract.
     *
     * @param _owner Address to initially own the contract.
     */
    function initialize(address _owner) public initializer {
        transferOwnership(_owner);
    }

    /**
     * Withdraws full ETH balance to the recipient.
     *
     * @param _to Address to receive the ETH balance.
     */
    function withdrawETH(address payable _to) public onlyOwner {
        _to.transfer(address(this).balance);
    }

    /**
     * Withdraws partial ETH balance to the recipient.
     *
     * @param _to Address to receive the ETH balance.
     * @param _amount Amount of ETH to withdraw.
     */
    function withdrawETH(address payable _to, uint256 _amount) public onlyOwner {
        _to.transfer(_amount);
    }

    /**
     * Withdraws full ERC20 balance to the recipient.
     *
     * @param _asset ERC20 token to withdraw.
     * @param _to Address to receive the ERC20 balance.
     */
    function withdrawERC20(ERC20 _asset, address _to) public onlyOwner {
        _asset.transfer(_to, _asset.balanceOf(address(this)));
    }

    /**
     * Withdraws partial ERC20 balance to the recipient.
     *
     * @param _asset ERC20 token to withdraw.
     * @param _to Address to receive the ERC20 balance.
     * @param _amount Amount of ERC20 to withdraw.
     */
    function withdrawERC20(
        ERC20 _asset,
        address _to,
        uint256 _amount
    ) public onlyOwner {
        _asset.transfer(_to, _amount);
    }

    /**
     * Withdraws ERC721 token to the recipient.
     *
     * @param _asset ERC721 token to withdraw.
     * @param _to Address to receive the ERC721 token.
     * @param _id Token ID of the ERC721 token to withdraw.
     */
    function withdrawERC721(
        ERC721 _asset,
        address _to,
        uint256 _id
    ) public onlyOwner {
        _asset.transferFrom(address(this), _to, _id);
    }
}
