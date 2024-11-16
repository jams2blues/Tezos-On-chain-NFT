# This smart contract has been writen to provide a simple way to mint editions of on-chain artwork with the Tezos blockchain
# It is written in the Legacy SmartPy programming language speicifally for use with the legacy.smartpy.io/ide compiler
# This contract is a combination of the oroginal Zero Contract (for 1/1) mixed with the SmartPy FA2 Template
# Author: jestemzero with assistance from ChatGPT, Gemini and Claude LLMs
# xTwiiter: @jestemzero
# Warpcast: @jestemzero
# Discord: @jestemzero

# IMPORTANT: On-chain artwork is saved with a datarUri format in the "artifactUri" metadata attribute
# Objkt.com currently does not recognize artifactUri strings longer than 254 characters
# Any token exceeding this limitation needs to contact Objkt.com directly and request the limitation be removed for their collection

import smartpy as sp

# Define contract metadata
contract_metadata = {
    "": sp.utils.bytes_of_string('tezos-storage:content'),
    "content": sp.utils.bytes_of_string(
        '{"name": "Project Name","description": "Project Description","interfaces": ["TZIP-012", "TZIP-016"],"authors": ["Author Name"],"authoraddress": ["Valid tz... address"],"symbol": "SYMBOL","creators": ["Valid tz... address"],"type":"art","imageUri":"URI string"}'
        )
}

class Error_message:
    def token_undefined(self):       return "FA2_TOKEN_UNDEFINED"
    def insufficient_balance(self):  return "FA2_INSUFFICIENT_BALANCE"
    def not_operator(self):          return "FA2_NOT_OPERATOR"
    def not_owner(self):             return "FA2_NOT_OWNER"
    def operators_unsupported(self): return "FA2_OPERATORS_UNSUPPORTED"
    def not_admin(self):             return "FA2_NOT_ADMIN"
    def not_admin_or_operator(self): return "FA2_NOT_ADMIN_OR_OPERATOR"
    def paused(self):                return "FA2_PAUSED"

class Batch_transfer:
    @staticmethod
    def get_transfer_type():
        tx_type = sp.TRecord(
            to_=sp.TAddress,
            token_id=sp.TNat,
            amount=sp.TNat
        ).layout(("to_", ("token_id", "amount")))
        
        transfer_type = sp.TRecord(
            from_=sp.TAddress,
            txs=sp.TList(tx_type)
        ).layout(("from_", "txs"))
        
        return transfer_type

    @staticmethod
    def get_type():
        return sp.TList(Batch_transfer.get_transfer_type())

    @staticmethod
    def item(from_, txs):
        v = sp.record(from_=from_, txs=txs)
        return sp.set_type_expr(v, Batch_transfer.get_transfer_type())

class Operator_param:
    @staticmethod
    def get_type():
        return sp.TRecord(
            owner=sp.TAddress,
            operator=sp.TAddress,
            token_id=sp.TNat
        ).layout(("owner", ("operator", "token_id")))

    @staticmethod
    def make(owner, operator, token_id):
        r = sp.record(
            owner=owner,
            operator=operator,
            token_id=token_id
        )
        return sp.set_type_expr(r, Operator_param.get_type())

class Ledger_key:
    @staticmethod
    def get_type():
        return sp.TPair(sp.TAddress, sp.TNat)

    @staticmethod
    def make(user, token):
        user = sp.set_type_expr(user, sp.TAddress)
        token = sp.set_type_expr(token, sp.TNat)
        result = sp.pair(user, token)
        return result

class Ledger_value:
    @staticmethod
    def get_type():
        return sp.TRecord(balance=sp.TNat).layout("balance")
        
    @staticmethod
    def make(balance):
        return sp.record(balance=balance)

class Operator_set:
    def inner_type(self):
        return sp.TRecord(
            owner=sp.TAddress,
            operator=sp.TAddress,
            token_id=sp.TNat
        ).layout(("owner", ("operator", "token_id")))

    def key_type(self):
        return self.inner_type()

    def make(self):
        return sp.big_map(tkey=self.key_type(), tvalue=sp.TUnit)

    def make_key(self, owner, operator, token_id):
        metakey = sp.record(
            owner=owner,
            operator=operator,
            token_id=token_id
        )
        return sp.set_type_expr(metakey, self.inner_type())

    def add(self, set, owner, operator, token_id):
        set[self.make_key(owner, operator, token_id)] = sp.unit

    def remove(self, set, owner, operator, token_id):
        del set[self.make_key(owner, operator, token_id)]

    def is_member(self, set, owner, operator, token_id):
        return set.contains(self.make_key(owner, operator, token_id))

class Balance_of:
    @staticmethod
    def request_type():
        return sp.TRecord(
            owner=sp.TAddress,
            token_id=sp.TNat
        ).layout(("owner", "token_id"))

    @staticmethod
    def response_type():
        return sp.TList(
            sp.TRecord(
                request=Balance_of.request_type(),
                balance=sp.TNat
            ).layout(("request", "balance")))

    @staticmethod
    def entrypoint_type():
        return sp.TRecord(
            callback=sp.TContract(Balance_of.response_type()),
            requests=sp.TList(Balance_of.request_type())
        ).layout(("requests", "callback"))

class Token_meta_data:
    def get_type(self):
        return sp.TRecord(
            token_id=sp.TNat,
            token_info=sp.TMap(sp.TString, sp.TBytes)
        ).layout(("token_id", "token_info"))

    def set_type_and_layout(self, expr):
        sp.set_type(expr, self.get_type())

class FA2_core(sp.Contract):
    def __init__(self, admin, metadata):
        self.error_message = Error_message()
        self.operator_set = Operator_set()
        self.init(
            ledger=sp.big_map(
                tkey=Ledger_key.get_type(),
                tvalue=Ledger_value.get_type()
            ),
            admin=admin,
            token_metadata=sp.big_map(
                tkey=sp.TNat,
                tvalue=Token_meta_data().get_type()
            ),
            operators=self.operator_set.make(),
            next_token_id=sp.nat(0),
            metadata=sp.big_map(metadata),
            paused=False,
            total_supply=sp.big_map(
                tkey=sp.TNat,
                tvalue=sp.TNat
            ),
            children=sp.set(t=sp.TAddress),
            parents=sp.set(t=sp.TAddress)
        )

    @sp.entry_point
    def transfer(self, params):
        sp.verify(~self.data.paused, message=self.error_message.paused())
        sp.set_type(params, Batch_transfer.get_type())
        
        sp.for transfer in params:
            sp.for tx in transfer.txs:
                sender_verify = ((transfer.from_ == sp.sender) |
                                 (sp.sender == self.data.admin) |
                                 (self.operator_set.is_member(self.data.operators,
                                                              transfer.from_,
                                                              sp.sender,
                                                              tx.token_id)))
                                                          
                sp.verify(sender_verify, message=self.error_message.not_operator())
                sp.verify(
                    self.data.token_metadata.contains(tx.token_id),
                    message=self.error_message.token_undefined()
                )
                
                sp.if (tx.amount > 0):
                    from_user = sp.pair(transfer.from_, tx.token_id)
                    sp.verify(
                        self.data.ledger.contains(from_user) & (self.data.ledger[from_user].balance >= tx.amount),
                        message=self.error_message.insufficient_balance())
                    
                    to_user = sp.pair(tx.to_, tx.token_id)
                    self.data.ledger[from_user].balance = sp.as_nat(
                        self.data.ledger[from_user].balance - tx.amount)
                    
                    sp.if self.data.ledger.contains(to_user):
                        self.data.ledger[to_user].balance += tx.amount
                    sp.else:
                        self.data.ledger[to_user] = Ledger_value.make(tx.amount)
    
    @sp.entry_point
    def mint(self, params):
        sp.set_type(params, sp.TRecord(
            to_=sp.TAddress,
            amount=sp.TNat,
            metadata=sp.TMap(sp.TString, sp.TBytes)
        ).layout(("to_", ("amount", "metadata"))))
        
        sp.verify(sp.sender == self.data.admin, message="Not authorized")
        
        token_id = self.data.next_token_id
        
        self.data.token_metadata[token_id] = sp.record(
            token_id=token_id,
            token_info=params.metadata
        )
        
        self.data.ledger[(params.to_, token_id)] = Ledger_value.make(params.amount)
        
        self.data.total_supply[token_id] = params.amount
        
        self.data.next_token_id += 1

    @sp.entry_point
    def balance_of(self, params):
        sp.verify(~self.data.paused, message=self.error_message.paused())
        sp.set_type(params, Balance_of.entrypoint_type())

        responses = sp.local('responses', sp.list([]))

        sp.for req in params.requests:
            sp.set_type(req, Balance_of.request_type())
            user = sp.pair(req.owner, req.token_id)
            sp.verify(self.data.token_metadata.contains(req.token_id),
                      message=self.error_message.token_undefined())

            sp.if self.data.ledger.contains(user):
                balance = self.data.ledger[user].balance
            sp.else:
                balance = sp.nat(0)

            responses.value.push(sp.record(
                request=req,
                balance=balance
            ))

        # Ensure responses are of the correct type
        sp.set_type(responses.value, Balance_of.response_type())

        sp.transfer(responses.value, sp.mutez(0), params.callback)

    @sp.entry_point
    def update_operators(self, params):
        sp.for update in params:
            with update.match_cases() as arg:
                with arg.match("add_operator") as upd:
                    sp.verify((upd.owner == sp.sender) | (sp.sender == self.data.admin),
                              message=self.error_message.not_admin_or_operator())
                    self.operator_set.add(self.data.operators,
                                          upd.owner,
                                          upd.operator,
                                          upd.token_id)
                with arg.match("remove_operator") as upd:
                    sp.verify((upd.owner == sp.sender) | (sp.sender == self.data.admin),
                              message=self.error_message.not_admin_or_operator())
                    self.operator_set.remove(self.data.operators,
                                             upd.owner,
                                             upd.operator,
                                             upd.token_id)

    @sp.entry_point
    def burn(self, params):
        sp.set_type(params, sp.TRecord(token_id=sp.TNat, amount=sp.TNat).layout(("token_id", "amount")))
        sp.verify(params.token_id < self.data.next_token_id, self.error_message.token_undefined())
        user = sp.pair(sp.sender, params.token_id)
    
        sp.verify(self.data.ledger.contains(user), self.error_message.not_owner())
        sp.verify(self.data.ledger[user].balance >= params.amount, self.error_message.insufficient_balance())
    
        self.data.ledger[user].balance = sp.as_nat(self.data.ledger[user].balance - params.amount)
        
        self.data.total_supply[params.token_id] = sp.as_nat(self.data.total_supply[params.token_id] - params.amount)
    
        sp.if self.data.ledger[user].balance == 0:
            del self.data.ledger[user]
                
    @sp.entry_point
    def add_child(self, address):
        sp.set_type(address, sp.TAddress)
        sp.verify(sp.sender == self.data.admin, "Only the contract owner can add children")
        self.data.children.add(address)
    
    @sp.entry_point
    def remove_child(self, address):
        sp.set_type(address, sp.TAddress)
        sp.verify(sp.sender == self.data.admin, "Only the contract owner can remove children")
        self.data.children.remove(address)
    
    @sp.entry_point
    def add_parent(self, address):
        sp.set_type(address, sp.TAddress)
        sp.verify(sp.sender == self.data.admin, "Only the contract owner can add parents")
        self.data.parents.add(address)
    
    @sp.entry_point
    def remove_parent(self, address):
        sp.set_type(address, sp.TAddress)
        sp.verify(sp.sender == self.data.admin, "Only the contract owner can remove parents")
        self.data.parents.remove(address)
        
    @sp.entry_point
    def set_pause(self, params):
        sp.verify(sp.sender == self.data.admin, message=self.error_message.not_admin())
        self.data.paused = params

    @sp.offchain_view(pure=True)
    def get_balance(self, req):
        sp.set_type(req, sp.TRecord(
            owner=sp.TAddress,
            token_id=sp.TNat
        ).layout(("owner", "token_id")))
        
        user = sp.pair(req.owner, req.token_id)
        sp.verify(self.data.token_metadata.contains(req.token_id),
                  message=self.error_message.token_undefined())
        sp.if self.data.ledger.contains(user):
            sp.result(self.data.ledger[user].balance)
        sp.else:
            sp.result(sp.nat(0))

    @sp.offchain_view(pure=True)
    def count_tokens(self):
        sp.result(self.data.next_token_id)

    @sp.offchain_view(pure=True)
    def does_token_exist(self, tok):
        sp.set_type(tok, sp.TNat)
        sp.result(self.data.token_metadata.contains(tok))

    @sp.offchain_view(pure=True)
    def all_tokens(self):
        sp.result(sp.range(0, self.data.next_token_id))

    @sp.offchain_view(pure=True)
    def total_supply(self, tok):
        sp.result(self.data.total_supply.get(tok, sp.nat(0)))

    @sp.offchain_view(pure=True)
    def is_operator(self, query):
        sp.set_type(query,
                    sp.TRecord(token_id=sp.TNat,
                               owner=sp.TAddress,
                               operator=sp.TAddress).layout(
                                   ("owner", ("operator", "token_id"))))
        sp.result(
            self.operator_set.is_member(self.data.operators,
                                        query.owner,
                                        query.operator,
                                        query.token_id)
        )

    @sp.offchain_view(pure=True)
    def get_children(self):
        sp.result(self.data.children)
    
    @sp.offchain_view(pure=True)
    def get_parents(self):
        sp.result(self.data.parents)
        

def add_test():
    @sp.add_test(name="NFT Editions Test Scenarios")
    def test():
        scenario = sp.test_scenario()

        # Test accounts
        admin = sp.test_account("Admin")
        artist = sp.test_account("Artist")
        collector1 = sp.test_account("Collector1")
        collector2 = sp.test_account("Collector2")

        scenario.h2("Accounts")
        scenario.show([admin, artist, collector1, collector2])
        
        # Contract deployment
        c1 = FA2_core(admin=admin.address, metadata=contract_metadata)
        scenario += c1

        scenario.h3("Mint Tokens")
        
        # Mint 10 copies of edition #1 (token_id 0) to artist
        edition1_md = sp.map(l={
            "": sp.utils.bytes_of_string("ipfs://QmZ1"),
            "name": sp.utils.bytes_of_string("Edition #1"),
            "symbol": sp.utils.bytes_of_string("ED1"),
            "decimals": sp.utils.bytes_of_string("0")
        })
        c1.mint(to_=artist.address, amount=10, metadata=edition1_md).run(sender=admin)

        # Mint 5 copies of edition #2 (token_id 1) to artist
        edition2_md = sp.map(l={
            "": sp.utils.bytes_of_string("ipfs://QmZ2"),
            "name": sp.utils.bytes_of_string("Edition #2"),
            "symbol": sp.utils.bytes_of_string("ED2"),
            "decimals": sp.utils.bytes_of_string("0")
        })
        c1.mint(to_=artist.address, amount=5, metadata=edition2_md).run(sender=admin)

        # Verify minting state for all tokens
        scenario.verify(c1.data.ledger[sp.pair(artist.address, 0)].balance == 10)  # Edition #1
        scenario.verify(c1.data.ledger[sp.pair(artist.address, 1)].balance == 5)   # Edition #2

        scenario.verify(c1.data.total_supply[0] == 10)  # Total supply for token_id 0
        scenario.verify(c1.data.total_supply[1] == 5)   # Total supply for token_id 1

        scenario.h3("Transfer Tests")
        
        # Test basic transfer using batch_transfer instance for token_id 0 and token_id 1
        c1.transfer(
            [
                Batch_transfer.item(
                    from_=artist.address,
                    txs=[
                        sp.record(to_=collector1.address, amount=3, token_id=0),  # Edition #1
                        sp.record(to_=collector2.address, amount=2, token_id=1)   # Edition #2
                    ]
                )
            ]
        ).run(sender=artist)

        # Verify balances after transfer
        scenario.verify(c1.data.ledger[sp.pair(artist.address, 0)].balance == 7)   # Edition #1
        scenario.verify(c1.data.ledger[sp.pair(collector1.address, 0)].balance == 3)  # Edition #1
        scenario.verify(c1.data.ledger[sp.pair(artist.address, 1)].balance == 3)   # Edition #2
        scenario.verify(c1.data.ledger[sp.pair(collector2.address, 1)].balance == 2)  # Edition #2

        scenario.h3("Balance Of Tests")

        # Use get_balance off-chain view
        balance_artist = scenario.compute(
            c1.get_balance(
                sp.record(owner=artist.address, token_id=0)
            )
        )

        balance_collector1 = scenario.compute(
            c1.get_balance(
                sp.record(owner=collector1.address, token_id=0)
            )
        )

        balance_collector2 = scenario.compute(
            c1.get_balance(
                sp.record(owner=collector2.address, token_id=0)
            )
        )

        total_balance = balance_artist + balance_collector1 + balance_collector2

        # Verify the total balance
        scenario.verify(total_balance == 10)

# Run the test
add_test()

# Compile the contract
sp.add_compilation_target(
    "nft_editions",
    FA2_core(
        admin=sp.address("tz1ADMIN_ADDRESS"),  # Replace with actual admin address when deploying
        metadata=contract_metadata
    )
)

