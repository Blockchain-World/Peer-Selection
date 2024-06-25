pragma solidity ^0.5.10;

import "./altbn128.sol";

library UTI {

    struct Deliverer {
        address payable deliverer_address;
        uint delivery_nums;
        uint total_amount;
        uint avg_speed;
        uint credibility;
        uint bid;
        bool is_selected;
    }
    
    // Functions for signature verification
    function splitSignature(bytes memory sig) internal pure returns (uint8 v, bytes32 r, bytes32 s){
        require(sig.length == 65);
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return (v, r, s);
    }
    
    function recoverSigner(bytes32 message, bytes memory sig) internal pure returns (address){
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(sig);
        return ecrecover(message, v, r, s);
    }
    
    function prefixed(bytes32 hash) internal pure returns (bytes32){
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }
    
}
