pragma solidity ^0.5.10;
pragma experimental ABIEncoderV2;

import {UTI} from "./Utility.sol";
import "./altbn128.sol";

/**
 * PeerSelection mode.
 **/

contract Main{

    using UTI for UTI.Deliverer;
    
    //event emitErk(uint, BN128Curve.G1Point, BN128Curve.G1Point, BN128Curve.G1Point, BN128Curve.G1Point);
    //event Debug(bytes32 VFDProof, bytes signature);
    //event Debug_1(uint now, uint timeout_dispute);
    //event SignerRecovered(address signer);
    //event ContractAddress(address contractAddress);

    address payable public provider;
    address payable public deliverer_d;

    //address payable public consumer;
    address payable public consumer = 0xFCAd0B19bB29D4674531d6f115237E16AfCE377c;
    BN128Curve.G1Point public vpk_consumer;

    // The set of credibility values of deliverers
    UTI.Deliverer[] deliverers;

    // The temp deliverer
    UTI.Deliverer deliver;
    
    // The deliverers obtained by the optimal selection algorithm
    uint[] selected_deliverers;

    //event Debug_2(UTI.Deliverer[] _deliverers, UTI.Deliverer _deliver, uint[] _selected_deliverers);
    //event Debug_3(address indexed  _sender);
    
    uint public timeout_round;
    uint public timeout_delivered;
    uint public timeout_dispute;
    uint public time_delivered;
    uint public end_time;
    
    enum state {started, joined, selected, ready, initiated, first_delivered, revealing}
    
    state public round;

    // The merkle root of the content m
    bytes32 public root_m = 0xcfd941c14535fc004b1668d312cdd472ac4df0903724ae1fcd544e924300033e;

    // the times of repeatable delivery
    uint public theta = 1;
    
    // The number of content chunks
    uint public n = 2;
    
    // The number of 32-byte sub-chunks in each content chunk: chunkSize / 32 (bytes32)
    uint constant chunkLength = 512;
    
    // The payment for delivery per chunk
    uint public payment_P = 0;
    
    // The payment for providing per chunk
    uint public payment_C = 0;

    // penalty fee to discourage the misbehavior of the provider
    uint public payment_pf = 0;
    
    // The number of delivered chunks
    uint public ctr = 0;

    // The start index (1-indexed) of request content
    uint public a = 0;
    
    modifier allowed(address addr, state s){
        require(now < timeout_round);
        require(round == s);
        require(msg.sender == addr);
        _;
    }
    
    function inState(state s) internal {
        round = s;
        timeout_round = now + 10 minutes;
    }
    
    constructor() payable public {
        provider = msg.sender; // store pk_P
        timeout_round = now;
    }
    
    // Phase I: Prepare (typically only need to be executed once)
    function start(bytes32 _root_m, uint _theta, uint _n, uint _payment_P, uint _payment_C, uint _payment_pf) payable public {
        require(msg.sender == provider);
        assert(msg.value >= _theta*(_payment_P*_n+_payment_pf));
        assert(_payment_C >= _payment_P);
        assert(_payment_pf >= _payment_C*_n/2); // the penalty fee is required to be proportional to the (n*payment_C) so the provider cannot delibrately low it
        root_m = _root_m;       // store root_m
        theta = _theta;         // store theta
        n = _n;                 // store n
        payment_P = _payment_P; // store payment_P
        payment_C = _payment_C; // store payment_C
        payment_pf = _payment_pf; // store payment_pf
        inState(state.started);
    }
    
    // The deliverer joins the smart contract
    function join(uint _bid) public {
        require(round == state.started);
        bool flag = false;
        for (uint i = 0; i < deliverers.length; i ++) {
            if (msg.sender == deliverers[i].deliverer_address) {
                flag = true;
                break;
            }
        }

        // If deliverer is a newly added peer to P2PCDN, initialize a basic information for it in deliverers.
        if (!flag) {
            deliver.deliverer_address = msg.sender;
            deliver.delivery_nums = 0;
            deliver.total_amount = 0;
            deliver.avg_speed = 0;
            deliver.credibility = 0;
            deliver.bid = _bid;
            deliver.is_selected = false;
            deliverers.push(deliver);
        }


        //emit Debug_2(deliverers, deliver, selected_deliverers);

        inState(state.joined);
    }


    // Deliverer select
    function select() public {
        require(round == state.joined);
        require(now < timeout_round);
        selected_deliverers.push(0);
        // Delegate authority to the selected optimital deliverer
        for (uint i = 0; i < selected_deliverers.length; i ++) {
            deliverers[selected_deliverers[i]].is_selected = true;
        }
        deliverer_d = deliverers[selected_deliverers[0]].deliverer_address;
        //emit Debug_2(deliverers, deliver, selected_deliverers);
        inState(state.selected);
    }
    
    // Determine whether it is the selected deliverer
    function prepared() allowed(deliverer_d, state.selected) public  {
        bool flag = false;
        //emit Debug_2(deliverers, deliver, selected_deliverers);
        // Determine whether the person executing the delivery has delivery authority
        for (uint i = 0; i < deliverers.length; i ++) {
            if (msg.sender == deliverers[i].deliverer_address) {
                if (deliverers[i].is_selected == true) {
                    flag = true;
                }
            }
        }
        require(flag == true);
        inState(state.ready);
    }
    
    // Phase II: Deliver
    function consume(BN128Curve.G1Point memory _vpk_consumer, uint _a) payable public {
        assert(msg.value >= (n - _a + 1) * payment_C);
        require(theta > 0);
        require(_a >= 1 && _a <= n);
        require(round == state.ready);
        a = _a;                        // store a
        consumer = msg.sender;         // store pk_C
        //consumer = 0xFCAd0B19bB29D4674531d6f115237E16AfCE377c;
        vpk_consumer = _vpk_consumer;  // store vpk_consumer
        timeout_delivered = now + 10 minutes; // start the timer
        inState(state.initiated);
    }
    
    //Send start chunk, to record its delivery start time
    function StChunk(uint _i) allowed(deliverer_d, state.initiated) public {
        // Record the index number of the first transferred content chunk
        a = _i;
        time_delivered = now;
        //start_time = block.timestamp;
        inState(state.first_delivered);
    }
    
    //**** PoDQ and VFDProof While verifying the number of distributed content chunks, update the deliverer dimension information
    function VrfPoDQ(uint _i, bytes memory _signature_C) allowed(deliverer_d, state.first_delivered) public returns (bool) {
        require(_i <= n);
        bytes32 VFDProof = UTI.prefixed(keccak256(abi.encodePacked(_i, consumer, msg.sender, root_m, this)));
        
        // emit Debug(VFDProof, _signature_C);
        // address signer = UTI.recoverSigner(VFDProof, _signature_C);
        // emit SignerRecovered(signer);
        // address contractAddr = address(this);
        //emit ContractAddress(contractAddr);

        if (UTI.recoverSigner(VFDProof, _signature_C) == consumer) {
            ctr = _i - a + 1; // update ctr
            consumer = msg.sender;
            end_time = now;
            uint num;
            for (uint i = 0; i < selected_deliverers.length; i ++) {
                if (deliverers[selected_deliverers[i]].deliverer_address == msg.sender) {
                    //update the dimensions of the deliverer the core of PoDQ
                    deliverers[num].delivery_nums = deliverers[num].delivery_nums + 1;
                    deliverers[num].total_amount = deliverers[num].total_amount + ctr * chunkLength;
                    deliverers[num].avg_speed = (deliverers[num].avg_speed + (ctr * chunkLength) / (end_time - time_delivered)) / 2;
                    break;
                }
            }
            return true;
        }
        return false;
    }
    
    // Timeout_delivered times out
    function deliveredTimeout() payable public {
        require(now > timeout_delivered);
        require(ctr >= 0 && ctr <= n);
        // if ctr is not updated (i.e., ctr == 0), the state will not be updated untill verifyVFDProof() 
        // is executed (i.e., the deliverer D claimed payment and update ctr)
        if ((ctr > 0) && (ctr <= n)) {
            if (ctr == n) {
                deliverer_d.transfer(payment_P*n);
            } else {
                provider.transfer(payment_P*(n-ctr));
                deliverer_d.transfer(payment_P*ctr);
            }
            inState(state.revealing);
            selfdestruct(deliverer_d);
        }
    }
    
    function delivered() payable allowed(consumer, state.initiated) public {
        require(now < timeout_delivered);
        require(ctr >= 0 && ctr <= n);
        // if ctr is not updated (i.e., ctr == 0), the state will not be updated untill verifyVFDProof()
        // is executed (i.e., the deliverer D claimed payment and update ctr)
        if ((ctr > 0) && (ctr <= n)) {
            if (ctr == n) {
                deliverer_d.transfer(payment_P*n);
            } else {
                provider.transfer(payment_P*(n-ctr));
                deliverer_d.transfer(payment_P*ctr);
            }
            inState(state.revealing);
            // selfdestruct(deliverer);
        }
    }
    
}
