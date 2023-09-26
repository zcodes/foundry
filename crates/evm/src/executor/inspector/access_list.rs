use alloy_primitives::{Address, B256};
use ethers::types::transaction::eip2930::{AccessList, AccessListItem};
use foundry_utils::types::{ToAlloy, ToEthers};
use hashbrown::{HashMap, HashSet};
use revm::{
    interpreter::{opcode, InstructionResult, Interpreter},
    Database, EVMData, Inspector,
};
use tracing::trace;

/// An inspector that collects touched accounts and storage slots.
#[derive(Default, Debug)]
pub struct AccessListTracer {
    excluded: HashSet<Address>,
    access_list: HashMap<Address, HashSet<B256>>,
}

impl AccessListTracer {
    pub fn new(
        access_list: AccessList,
        from: Address,
        to: Address,
        precompiles: Vec<Address>,
    ) -> Self {
        AccessListTracer {
            excluded: [from, to].iter().chain(precompiles.iter()).copied().collect(),
            access_list: access_list
                .0
                .iter()
                .map(|v| {
                    (
                        v.address.to_alloy(),
                        v.storage_keys.iter().copied().map(|v| v.to_alloy()).collect(),
                    )
                })
                .collect(),
        }
    }
    pub fn access_list(&self) -> AccessList {
        trace!("xx: access_list: !!");
        AccessList::from(
            self.access_list
                .iter()
                .map(|(address, slots)| AccessListItem {
                    address: address.to_ethers(),
                    storage_keys: slots.iter().copied().map(|k| k.to_ethers()).collect(),
                })
                .collect::<Vec<AccessListItem>>(),
        )
    }
}
impl<DB: Database> Inspector<DB> for AccessListTracer {
    #[inline]
    fn step(
        &mut self,
        interpreter: &mut Interpreter,
        _data: &mut EVMData<'_, DB>,
    ) -> InstructionResult {
        trace!("xx: opcode: {:?}", opcode::OpCode::new(interpreter.current_opcode()).unwrap().as_str());
        trace!("xx: stack: {:?}", interpreter.stack);
        trace!("xx: depth: {:?}", interpreter.stack.depth);
        match interpreter.current_opcode() {
            opcode::SLOAD | opcode::SSTORE => {
                if let Ok(slot) = interpreter.stack().peek(0) {
                    let cur_contract = interpreter.contract.address;
                    trace!("xx: slot1: {:?} !", slot);
                    trace!("xx: addr1: {} !", cur_contract);
                    self.access_list.entry(cur_contract).or_default().insert(slot.into());
                } else {
                    trace!("xx: not ok1 !")
                }
            }
            opcode::EXTCODECOPY |
            opcode::EXTCODEHASH |
            opcode::EXTCODESIZE |
            opcode::BALANCE |
            opcode::SELFDESTRUCT => {
                if let Ok(slot) = interpreter.stack().peek(0) {
                    let addr: Address = Address::from_word(slot.into());
                    trace!("xx: addr1: {}", addr);
                    if !self.excluded.contains(&addr) {
                        self.access_list.entry(addr).or_default();
                    } else {
                        trace!("xx: exclude: {}", addr)
                    }
                } else {
                    trace!("xx: not ok2 !")
                }
            }
            opcode::DELEGATECALL | opcode::CALL | opcode::STATICCALL | opcode::CALLCODE => {
                if let Ok(slot) = interpreter.stack().peek(1) {
                    let addr: Address = Address::from_word(slot.into());
                    trace!("xx: addr2: {}", addr);
                    if !self.excluded.contains(&addr) {
                        self.access_list.entry(addr).or_default();
                    } else {
                        trace!("xx: exclude2: {}", addr);
                    }
                } else {
                    trace!("xx: not ok3 !");
                }
            }
            _ => (),
        }
        InstructionResult::Continue
    }
}
