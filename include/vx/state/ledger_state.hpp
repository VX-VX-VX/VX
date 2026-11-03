#pragma once

#include "vx/blockchain/block.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/blockchain/genesis.hpp"
#include "vx/core/u128.hpp"
#include "vx/crypto/pq_signature.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

namespace vx::state {

using blockchain::Address;
using blockchain::Transaction;
using blockchain::BlockView;
using core::U128;

/// FNV-1a over the 42-byte NFA payload.
struct AddressHash {
    size_t operator()(const Address& a) const noexcept {
        uint64_t h = 1469598103934665603ull;
        for (uint8_t b : a) {
            h ^= b;
            h *= 1099511628211ull;
        }
        return static_cast<size_t>(h);
    }
};

/// Result of applying a block to the ledger.
struct ApplyResult {
    bool ok = false;
    uint64_t transfers = 0;
    std::string error;
    U128 fees_burned;
    U128 fees_miner_reward;
};

/**
 * @brief In-memory UTXO-free balance table (address -> atomic units).
 * Blocks are applied strictly in height order; every transfer is verified
 * against the sender balance before mutation, so no negative balance or
 * supply inflation can enter the state.
 */
class LedgerState {
public:
    LedgerState() {
        // PQ seed bindings (BACKLOG 0.7): the protocol-level binding table
        // is part of consensus state, computed identically on every node.
        for (const auto& b : blockchain::pq_seed_bindings()) {
            pq_roots_[b.addr] = b.root;
        }
    }

    /// Binds an address to the XMSS root of the key authorized to spend
    /// from it. Idempotent for the same root; a DIFFERENT root for an
    /// already-bound address is refused (root rotation is BACKLOG 0.8
    /// follow-up and must itself be witness-authorized when it ships).
    bool bind_pq_sender(const Address& a, const std::array<uint8_t, 32>& root) {
        auto it = pq_roots_.find(a);
        if (it != pq_roots_.end()) return it->second == root;
        pq_roots_[a] = root;
        return true;
    }

    /// The bound root for an address, if any.
    bool pq_root_of(const Address& a, std::array<uint8_t, 32>& out) const {
        auto it = pq_roots_.find(a);
        if (it == pq_roots_.end()) return false;
        out = it->second;
        return true;
    }

    /// Applies all transactions of a block. Rejects blocks whose height does
    /// not match the expected next height (state must track the chain tip).
    ApplyResult apply_block(const BlockView& block) {
        ApplyResult res;

        if (block.header().block_height != next_height_) {
            res.error = "height gap: expected " + std::to_string(next_height_) +
                        ", got " + std::to_string(block.header().block_height);
            return res;
        }

        uint32_t n = block.header().tx_count;
        // Structural bound: a frame cannot carry more transactions than the
        // fixed 64 KiB layout allows. Unchecked, tx_count from a hostile
        // frame walks BlockView::tx(i) past the frame's transaction array
        // and past the frame itself.
        if (n > blockchain::MAX_TX_PER_BLOCK) {
            res.error = "tx_count " + std::to_string(n) +
                        " exceeds block capacity " +
                        std::to_string(blockchain::MAX_TX_PER_BLOCK);
            return res;
        }
        std::vector<U128> debits(n);
        std::vector<U128> fees(n);
        // Intra-block pending credits for intra-block spendability.
        std::unordered_map<Address, U128, AddressHash> pending_;
        // Intra-block DEBITS per sender (amount + fee, cumulative). Without
        // this, two spends of the same sender each pass the balance check
        // independently and the commit loop underflows U128 — minting an
        // astronomically large phantom balance (external review P0, fixed).
        std::unordered_map<Address, U128, AddressHash> intra_debits_;

 // verify every sender has sufficient funds + nonce.
        // Track expected nonce per sender within this block (for intra-block sequential nonce)
        std::unordered_map<Address, uint32_t, AddressHash> expected_nonces_;
        // Self-certifying bindings produced by this block's pre-check loop;
        // applied only after every transaction validated (see round-7 note).
        std::vector<std::pair<Address, std::array<uint8_t, 32>>> new_bindings_;

        // Legacy Genesis v1 exemption (fee=0/nonce=0 skips nonce accounting)
        // is scoped to the actual genesis replay window. Unscoped, ANY user
        // transaction with fee=0/nonce=0 would bypass nonce checks forever
        // (external review P0: unbounded nonce-0 replay).
        const bool legacy_window = (next_height_ <= 1);
        // At most one GENESIS_2 mint per height-1 block (see check below).
        bool genesis_mint_seen = false;

        for (uint32_t i = 0; i < n; ++i) {
            const Transaction& tx = block.tx(i);

            Address sender = blockchain::tx_address(tx.sender_nfa);
            uint64_t amount = blockchain::tx_amount(tx);
            uint32_t fee = blockchain::tx_fee(tx);
            uint32_t nonce = blockchain::tx_nonce(tx);

            // Check for Genesis v1 transaction (backward compatibility)
            bool is_genesis_v1 = blockchain::is_genesis_v1_tx(tx);

            // Hardened Minting Rules.
            const char* s = reinterpret_cast<const char*>(sender.data());
            bool is_genesis = (std::strncmp(s, "GENESIS", 7) == 0);
            bool is_miner   = (std::strncmp(s, "MINER_", 6) == 0);

            // ── Authorization (BACKLOG 0.7, closed 2026-11-03): system
            // senders keep the structural integrity digest; every USER
            // sender requires a post-quantum witness. The keyless Tier-2
            // digest check authorizes anyone (the digest needs no key —
            // the reviewer moved 1 VX out of the genesis receiver with it),
            // so it no longer accepts anything on the consensus path.
            if (is_genesis || is_miner) {
                if (is_miner) {
                    // BACKLOG 0.6 remainder closed (2026-11-03): the coinbase
                    // is bound to the chain position - receiver + height +
                    // previous tip hash. The keyless digest no longer
                    // authorizes emissions, and a coinbase copied from one
                    // fork cannot be replayed on a competing fork at the
                    // same height (its tag commits the OTHER fork's tip).
                    uint8_t expect_tag[12];
                    blockchain::coinbase_binding(expect_tag,
                                                 blockchain::tx_address(tx.receiver_nfa),
                                                 block.header().block_height,
                                                 block.header().prev_block_hash);
                    if (std::memcmp(tx.cocoon_proof, expect_tag, 12) != 0) {
                        res.error = "tx " + std::to_string(i) +
                                    ": coinbase is not bound to this chain position";
                        return res;
                    }
                } else if (!blockchain::verify_transaction_proof(tx)) {
                    res.error = "tx " + std::to_string(i) + ": invalid cocoon_proof";
                    return res;
                }
            } else {
                vx::crypto::pq::PqSignatureWitness w;
                std::string pq_err;
                if (!blockchain::verify_pq_witness(tx, nullptr, &w, &pq_err)) {
                    res.error = "tx " + std::to_string(i) + ": " + pq_err;
                    return res;
                }
                std::array<uint8_t, 32> bound{};
                if (pq_root_of(sender, bound)) {
                    if (std::memcmp(bound.data(), w.pq_pubkey_root.data(), 32) != 0) {
                        res.error = "tx " + std::to_string(i) +
                                    ": PQ witness root does not match the sender's bound key";
                        return res;
                    }
                } else if (blockchain::is_pq_address(sender)) {
                    // Self-certifying binding: the address commits its own
                    // key root, so the first witnessed spend binds it.
                    Address chk{};
                    blockchain::derive_pq_address(w.pq_pubkey_root.data(), chk.data());
                    if (chk != sender) {
                        res.error = "tx " + std::to_string(i) +
                                    ": PQ witness root does not derive the sender address";
                        return res;
                    }
                    // Round-7 hardening: bindings collected, applied only
                    // after the WHOLE block validates - a rejected block
                    // must not mutate consensus state.
                    new_bindings_.emplace_back(sender, w.pq_pubkey_root);
                } else {
                    res.error = "tx " + std::to_string(i) +
                                ": sender address is not PQ-bound; keyless transfers are"
                                " rejected (BACKLOG 0.7)";
                    return res;
                }
            }

            // Allow zero amount for MINER_ coinbase (actual reward computed from fees)
            if (amount == 0 && !is_miner) {
                res.error = "tx " + std::to_string(i) + ": zero transfer";
                return res;
            }

            if (is_genesis || is_miner) {
                if (is_genesis) {
                    if (next_height_ > 0 && !(next_height_ == 1 &&
                        std::strncmp(s, "GENESIS_2", 9) == 0 &&
                        !tracked_addresses_containing(blockchain::tx_address(tx.receiver_nfa)))) {
                        res.error = "tx " + std::to_string(i) + ": GENESIS mint unauthorized at height " + std::to_string(next_height_);
                        return res;
                    }
                    // The untracked-receiver check above reads committed
                    // balances_, and balances_ only changes in the commit
                    // loop AFTER this pre-check - so within one block every
                    // further mint also saw its receiver as "untracked" and
                    // a single height-1 block could mint unlimited GENESIS_2
                    // supply (N x 100k VX). Enforce one mint per block.
                    if (next_height_ == 1) {
                        if (genesis_mint_seen) {
                            res.error = "tx " + std::to_string(i) +
                                        ": second GENESIS mint in one block";
                            return res;
                        }
                        genesis_mint_seen = true;
                    }
                }
                if (is_miner) {
                    if (i != 0) {
                        res.error = "tx " + std::to_string(i) + ": MINER_ must be index 0";
                        return res;
                    }
                    U128 max_reward = U128(1000ULL * 100000000ULL);
                    if (U128(amount) > max_reward) {
                        res.error = "tx " + std::to_string(i) + ": reward exceeds limit";
                        return res;
                    }
                }
                // Coinbase transactions don't pay fees
                fees[i] = U128{0};
            } else {
                // Regular transfer: check balance + nonce.
                // Nonce replay protection - check against intra-block expected nonce
                uint32_t expected_nonce = 0;
                auto nit = expected_nonces_.find(sender);
                if (nit == expected_nonces_.end()) {
                    expected_nonce = get_next_nonce(sender);
                    expected_nonces_[sender] = expected_nonce;
                } else {
                    expected_nonce = nit->second;
                }

                if (!(legacy_window && is_genesis_v1) && nonce != expected_nonce) {
                    res.error = "tx " + std::to_string(i) + ": nonce mismatch (expected " +
                                std::to_string(expected_nonce) + ", got " + std::to_string(nonce) + ")";
                    return res;
                }

                U128 total_cost = U128(amount) + U128(fee);
                U128 balance = balance_of(sender);
                auto pit = pending_.find(sender);
                if (pit != pending_.end()) balance = balance + pit->second;
                // Subtract this sender's earlier spends IN THE SAME BLOCK
                // (checked): each tx must be validated against the balance
                // the commit loop will actually see.
                auto dit = intra_debits_.find(sender);
                if (dit != intra_debits_.end()) {
                    if (dit->second > balance) {
                        res.error = "tx " + std::to_string(i) + ": insufficient funds";
                        return res;
                    }
                    balance = balance - dit->second;
                }
                if (balance < total_cost) {
                    res.error = "tx " + std::to_string(i) + ": insufficient funds";
                    return res;
                }
                // Accumulate the debit NOW (checked add). Real debit sums
                // are bounded by total supply (~2.6e14 atomics), far below
                // 2^64; anything larger is refused instead of wrapping.
                const U128 this_debit = U128(amount) + U128(fee);
                U128 acc = U128{};
                auto ait = intra_debits_.find(sender);
                if (ait != intra_debits_.end()) acc = ait->second;
                if (acc > U128(0xFFFFFFFFFFFFFFFFULL) ||
                    this_debit > U128(0xFFFFFFFFFFFFFFFFULL) - acc) {
                    res.error = "tx " + std::to_string(i) + ": debit accumulator overflow";
                    return res;
                }
                intra_debits_[sender] = acc + this_debit;
                fees[i] = U128(fee);
            }
            debits[i] = U128(amount);
            Address receiver = blockchain::tx_address(tx.receiver_nfa);
            pending_[receiver] = pending_[receiver] + U128(amount);

            // Update expected nonce for next transaction from same sender
            if (!is_genesis && !is_miner && !is_genesis_v1) {
                expected_nonces_[sender] = expected_nonces_[sender] + 1;
            }
        }

        // Round-7 hardening: every transaction in the block validated, so
        // the self-certifying bindings collected during the pre-check are
        // safe to commit now. A block rejected anywhere above leaves
        // pq_roots_ untouched (the old code bound the sender mid-loop,
        // before later transactions could still refuse the block).
        for (const auto& [addr, root] : new_bindings_) {
            bind_pq_sender(addr, root);
        }
        new_bindings_.clear();

 // commit with TDI fee burn (50% burned, 50% to miner)
        U128 total_fees{0};
        for (uint32_t i = 0; i < n; ++i) {
            total_fees = total_fees + fees[i];
        }
        U128 burned = total_fees / U128(2);
        U128 miner_reward = total_fees - burned; // Handles odd division

        for (uint32_t i = 0; i < n; ++i) {
            const Transaction& tx = block.tx(i);
            Address sender = blockchain::tx_address(tx.sender_nfa);
            Address receiver = blockchain::tx_address(tx.receiver_nfa);

            const char* s = reinterpret_cast<const char*>(sender.data());
            bool is_coinbase = (std::strncmp(s, "GENESIS", 7) == 0) ||
                               (std::strncmp(s, "MINER_", 6) == 0);

            if (!is_coinbase) {
                // Hard underflow guard (defense in depth): the pre-check
                // loop's intra_debits_ accounting makes this unreachable;
                // if it ever fired, refusing is better than minting a
                // 2^128 phantom balance.
                const U128 outflow = debits[i] + fees[i];
                if (balances_[sender] < outflow) {
                    res.error = "tx " + std::to_string(i) + ": internal underflow guard";
                    return res;
                }
                balances_[sender] = balances_[sender] - outflow;
                // Update nonce for non-genesis-v1 transactions
                if (!(legacy_window && blockchain::is_genesis_v1_tx(tx))) {
                    set_next_nonce(sender, blockchain::tx_nonce(tx) + 1);
                }
            }
            balances_[receiver] = balances_[receiver] + debits[i];
        }

        // Track burned supply
        burned_supply_ = burned_supply_ + burned;

        ++next_height_;
        res.ok = true;
        res.transfers = n;
        res.fees_burned = burned;
        res.fees_miner_reward = miner_reward;
        return res;
    }

    U128 balance_of(const Address& a) const {
        auto it = balances_.find(a);
        return it == balances_.end() ? U128{} : it->second;
    }

    /// Get next expected nonce for an address
    uint32_t get_next_nonce(const Address& a) const {
        auto it = nonces_.find(a);
        return it == nonces_.end() ? 0 : it->second;
    }

    /// Set next expected nonce for an address
    void set_next_nonce(const Address& a, uint32_t nonce) {
        nonces_[a] = nonce;
    }

    uint64_t applied_height() const noexcept { return next_height_ - 1; }
    uint64_t next_expected_height() const noexcept { return next_height_; }
    size_t tracked_addresses() const noexcept { return balances_.size(); }

    /// Check if an address has ever been recorded in the state (even with 0 balance).
    bool tracked_addresses_containing(const Address& a) const noexcept {
        return balances_.find(a) != balances_.end();
    }

    /// Exposes the full active account map for RPC enumeration.
    const std::unordered_map<Address, U128, AddressHash>& accounts() const noexcept {
        return balances_;
    }

    /// Total atomics in circulation (sanity invariant against supply inflation).
    U128 total_supply() const noexcept {
        U128 sum{};
        for (const auto& [addr, bal] : balances_) {
            // Checked accumulation: with per-sender intra-block debits
            // enforced in apply_block, balances cannot wrap - but this
            // sum must never silently mask a corrupted state either.
            if (bal > U128(0xFFFFFFFFFFFFFFFFULL) ||
                sum > U128(0xFFFFFFFFFFFFFFFFULL) - bal) {
                return U128(0xFFFFFFFFFFFFFFFFULL); // saturated: caller must treat as anomaly
            }
            sum = sum + bal;
        }
        return sum;
    }

    /// Total burned supply (TDI burn)
    U128 total_burned() const noexcept { return burned_supply_; }

    /// Renders an address with its NFA_V6_ prefix for display.
    static std::string address_label(const Address& a) {
        return "NFA_V6_" + std::string(reinterpret_cast<const char*>(a.data()), 42);
    }

    /// Rewind helper: adjust balance directly for reorg / undo
    void adjust_balance(const Address& a, U128 delta, bool add) {
        if (add) {
            balances_[a] = balances_[a] + delta;
        } else {
            if (balances_[a] >= delta) {
                balances_[a] = balances_[a] - delta;
            } else {
                balances_[a] = U128{0};
            }
        }
    }

    /// Set height directly for reorg
    void set_next_height(uint64_t h) noexcept { next_height_ = h; }

private:
    std::unordered_map<Address, U128, AddressHash> balances_;
    std::unordered_map<Address, uint32_t, AddressHash> nonces_;
    std::unordered_map<Address, std::array<uint8_t, 32>, AddressHash> pq_roots_;
    U128 burned_supply_{0};
    uint64_t next_height_ = 0;
};

} // namespace vx::state