# Coverage Gap Analysis

**Generated**: 2026-01-22
**Purpose**: Identify uncovered code sections and create targeted test plan to reach coverage thresholds

## Current Coverage Status

| Crate | Current | Target | Gap | Priority |
|-------|---------|--------|-----|----------|
| txgate-crypto | 69.6% | 100% | 30.4% | HIGH (security-critical) |
| txgate-chain | 67.2% | 100% | 32.8% | HIGH (security-critical) |
| txgate-policy | 68.5% | 100% | 31.5% | HIGH (security-critical) |
| txgate-core | 98.1% | 90% | ✅ PASS | - |
| txgate | 71.2% | 80% | 8.8% | MEDIUM |

## Detailed Gap Analysis by Crate

### 1. txgate-crypto (69.6% → 100%)

**Gap: ~30%** | **Estimated Missing Tests: 25-30**

#### A. Error Handling Paths (Priority: HIGH)

1. **encryption.rs - Argon2 failures**
   - **Location**: `derive_key()` line 263
   - **Issue**: `StoreError::EncryptionFailed` from Argon2 never tested
   - **Test needed**: Mock/force Argon2 parameter error
   - **Impact**: 2-3% coverage

2. **encryption.rs - ChaCha20 creation failure**
   - **Location**: `encrypt_key()` line 327
   - **Issue**: `ChaCha20Poly1305::new()` error path untested
   - **Test needed**: Invalid nonce scenarios
   - **Impact**: 2% coverage

3. **store.rs - File I/O errors**
   - **Location**: `FileKeyStore::store()`, `load()`, `delete()`
   - **Issue**: File permission failures, read/write errors not covered
   - **Test needed**:
     - Readonly filesystem
     - Permission denied errors
     - Disk full scenarios
   - **Impact**: 8-10% coverage

#### B. Cryptographic Edge Cases (Priority: HIGH)

4. **keypair.rs - Signature normalization**
   - **Location**: `normalize_s()` lines 537-550
   - **Issue**: Both normalization branches (when normalized and when not) not fully tested
   - **Test needed**:
     - High-S signature requiring normalization
     - Low-S signature not requiring normalization
     - Recovery ID flip verification
   - **Impact**: 3-4% coverage

5. **keypair.rs - Generate unreachable path**
   - **Location**: `Secp256k1KeyPair::generate()` line 507
   - **Issue**: `unreachable!()` in error case has no coverage
   - **Test needed**: Document why this is unreachable with property test
   - **Impact**: 1% coverage

#### C. Platform-Specific Code (Priority: MEDIUM)

6. **store.rs - Windows permission handling**
   - **Location**: `cfg(not(unix))` blocks
   - **Issue**: Windows-specific permission code never executed in CI
   - **Test needed**: Windows CI runner or conditional compilation tests
   - **Impact**: 5-6% coverage

7. **store.rs - Concurrent access**
   - **Location**: All FileKeyStore methods
   - **Issue**: Race conditions and concurrent access not tested
   - **Test needed**: Multi-threaded test with concurrent read/write
   - **Impact**: 2-3% coverage

#### D. Trait Implementations (Priority: LOW)

8. **Exhaustive trait coverage**
   - **Issue**: Some From/Into conversions may not be exercised
   - **Test needed**: Explicit trait usage tests
   - **Impact**: 1-2% coverage

---

### 2. txgate-chain (67.2% → 100%)

**Gap: ~33%** | **Estimated Missing Tests: 30-35**

#### A. Ethereum Parser Errors (Priority: HIGH)

1. **ethereum.rs - Missing field handlers**
   - **Location**: Lines 125-155
   - **Issue**: Error paths for missing transaction fields not tested:
     - Missing `nonce` (line 125-128)
     - Missing `to` (line 137-140)
     - Missing `value` (line 142-145)
     - Missing `data` (line 147-150)
     - Missing `v` (line 152-155)
   - **Test needed**: 5 tests with malformed transactions
   - **Impact**: 6-8% coverage

2. **ethereum.rs - ERC-20 fallback**
   - **Location**: `analyze_erc20()` line 187
   - **Issue**: None return path not exercised
   - **Test needed**: Transaction with invalid ERC-20 calldata
   - **Impact**: 2% coverage

#### B. ERC-20 Parsing Edge Cases (Priority: HIGH)

3. **erc20.rs - Truncated calldata**
   - **Location**: Lines 68-100
   - **Issue**: Valid selector with truncated parameters not tested
   - **Test needed**:
     - Transfer with calldata < 68 bytes
     - Approve with calldata < 68 bytes
     - TransferFrom with calldata < 100 bytes
   - **Impact**: 5-6% coverage

4. **erc20.rs - Invalid address extraction**
   - **Location**: Address parsing at bytes 12-32
   - **Issue**: Short data buffers not tested
   - **Test needed**: Calldata with valid selector but < 32 byte params
   - **Impact**: 3% coverage

5. **erc20.rs - All Erc20Call variants**
   - **Location**: `is_transfer()`, `is_approval()` methods
   - **Issue**: Not all enum variants tested in boolean checks
   - **Test needed**: Exhaustive variant coverage
   - **Impact**: 2-3% coverage

#### C. RLP Decoding Errors (Priority: HIGH)

6. **rlp.rs - Malformed structures**
   - **Location**: `Header::decode_bytes()` line 231-233
   - **Issue**: Invalid RLP format error paths not tested
   - **Test needed**:
     - Truncated RLP data
     - Invalid length prefixes
     - Malformed list structures
     - Empty input
   - **Impact**: 8-10% coverage

7. **rlp.rs - Boundary conditions**
   - **Location**: `data.get(1..).unwrap_or_default()` line 179
   - **Issue**: Boundary case when length = 0 or 1
   - **Test needed**: RLP with edge-case lengths
   - **Impact**: 2% coverage

#### D. Display/Debug Implementations (Priority: LOW)

8. **RiskLevel::Display**
   - **Location**: Lines 50-58
   - **Issue**: Display trait not tested
   - **Test needed**: Format all risk levels
   - **Impact**: 1-2% coverage

9. **TokenInfo serialization**
   - **Issue**: JSON serialization edge cases not tested
   - **Test needed**: Round-trip with special characters
   - **Impact**: 1% coverage

#### E. Registry Operations (Priority: MEDIUM)

10. **tokens.rs - Address parsing failures**
    - **Location**: `with_builtins()` lines 129-149
    - **Issue**: Invalid address strings not tested
    - **Test needed**: Malformed addresses in registry
    - **Impact**: 2-3% coverage

11. **tokens.rs - Unknown address lookup**
    - **Location**: `get_or_default()`
    - **Issue**: Fallback behavior may not be tested
    - **Test needed**: Query non-existent token
    - **Impact**: 1% coverage

---

### 3. txgate-policy (68.5% → 100%)

**Gap: ~31.5%** | **Estimated Missing Tests: 25-30**

#### A. Policy Check Result Variants (Priority: HIGH)

1. **PolicyCheckResult reason generation**
   - **Location**: Lines 181-184 in types
   - **Issue**: Each denial reason variant not tested:
     - `DeniedBlacklisted` reason message
     - `DeniedNotWhitelisted` reason message
     - `DeniedExceedsTransactionLimit` reason message (with amount)
     - `DeniedExceedsDailyLimit` reason message (with limit)
   - **Test needed**: 4 tests generating each denial type
   - **Impact**: 6-8% coverage

#### B. Daily Limit Boundary Cases (Priority: HIGH)

2. **U256 boundary arithmetic**
   - **Location**: Daily limit checks in engine.rs
   - **Issue**: Boundary conditions not tested:
     - amount == limit (should allow)
     - daily_total + amount == limit (boundary)
     - daily_total + amount overflows U256
     - U256::MAX amounts
   - **Test needed**: 4 boundary tests
   - **Impact**: 5-6% coverage

3. **Daily limit reset behavior**
   - **Location**: `TransactionHistory::daily_total()`
   - **Issue**: Date boundary and reset logic not tested
   - **Test needed**:
     - Query for different dates
     - Midnight rollover scenario
     - Multiple days in history
   - **Impact**: 3-4% coverage

#### C. Policy Evaluation Edge Cases (Priority: HIGH)

4. **None recipient handling**
   - **Location**: Blacklist/whitelist checks
   - **Issue**: Policy evaluation with None recipients not tested
   - **Test needed**: Transactions without recipient field
   - **Impact**: 4-5% coverage

5. **Whitelist empty vs. disabled**
   - **Location**: Whitelist check logic
   - **Issue**: Difference between empty whitelist and disabled not tested
   - **Test needed**:
     - Whitelist enabled with empty list (deny all)
     - Whitelist disabled (allow all)
   - **Impact**: 3% coverage

6. **Zero-amount transactions**
   - **Location**: Amount limit checks
   - **Issue**: Zero amounts passing through limits not tested
   - **Test needed**: Transaction with amount = 0
   - **Impact**: 2% coverage

#### D. Transaction History Error Paths (Priority: MEDIUM)

7. **Database operation failures**
   - **Location**: `TransactionHistory` all methods
   - **Issue**: SQLite error paths not tested:
     - Connection failures
     - Query errors
     - Constraint violations
   - **Test needed**: Mock database failures
   - **Impact**: 6-8% coverage

8. **Concurrent access**
   - **Location**: All history operations
   - **Issue**: Race conditions and concurrent transactions not tested
   - **Test needed**: Multi-threaded test with concurrent inserts/queries
   - **Impact**: 2-3% coverage

9. **Duplicate transaction recording**
   - **Location**: `record()` method
   - **Issue**: Same transaction hash recorded multiple times not tested
   - **Test needed**: Record same hash twice
   - **Impact**: 1-2% coverage

---

### 4. txgate (71.2% → 80%)

**Gap: ~9%** | **Estimated Missing Tests: 10-12**

#### A. CLI Error Paths (Priority: MEDIUM)

1. **Command execution failures**
   - **Location**: CLI command handlers
   - **Issue**: Error paths in command execution not tested
   - **Test needed**:
     - Invalid arguments
     - Missing required files
     - Permission errors
   - **Impact**: 3-4% coverage

#### B. Configuration Loading (Priority: MEDIUM)

2. **Invalid configuration handling**
   - **Location**: Config loading
   - **Issue**: Parse errors not tested:
     - Invalid TOML syntax
     - Missing required fields
     - Type conversion errors
     - Out-of-range values
   - **Test needed**: 4 tests with malformed configs
   - **Impact**: 3-4% coverage

#### C. Audit Logging (Priority: LOW)

3. **Logging error paths**
   - **Location**: Audit log writing
   - **Issue**: Permission and I/O errors not tested
   - **Test needed**:
     - Readonly log directory
     - Disk full scenarios
   - **Impact**: 2-3% coverage

---

## Prioritized Test Implementation Plan

### Phase 1: High-Impact Security Paths (Target: +15% total coverage)

**Duration**: 2-3 hours
**Focus**: Error handling in security-critical crypto and parsing code

1. **txgate-crypto** - File I/O errors (8-10%)
2. **txgate-chain** - RLP decoding errors (8-10%)
3. **txgate-policy** - U256 boundary cases (5-6%)

### Phase 2: Parser Edge Cases (Target: +10% total coverage)

**Duration**: 1-2 hours
**Focus**: Transaction parsing and ERC-20 edge cases

4. **txgate-chain** - Ethereum missing fields (6-8%)
5. **txgate-chain** - ERC-20 truncated calldata (5-6%)
6. **txgate-crypto** - Signature normalization (3-4%)

### Phase 3: Policy Logic Completeness (Target: +8% total coverage)

**Duration**: 1-2 hours
**Focus**: Policy evaluation branches and denial reasons

7. **txgate-policy** - PolicyCheckResult variants (6-8%)
8. **txgate-policy** - None recipient handling (4-5%)
9. **txgate-policy** - Database errors (6-8%)

### Phase 4: CLI and Config (Target: +7% for txgate)

**Duration**: 1 hour
**Focus**: User-facing error paths

10. **txgate** - CLI error paths (3-4%)
11. **txgate** - Config loading errors (3-4%)

### Phase 5: Remaining Coverage (Target: Fill gaps to 100%/80%)

**Duration**: 2-3 hours
**Focus**: Platform-specific code, Display traits, concurrent access

12. All remaining gaps from priority lists above

---

## Expected Coverage After Implementation

| Crate | Current | After Phase 1-2 | After Phase 3-4 | Final Target |
|-------|---------|-----------------|-----------------|--------------|
| txgate-crypto | 69.6% | 85-88% | 92-95% | 98-100% |
| txgate-chain | 67.2% | 85-90% | 95-98% | 98-100% |
| txgate-policy | 68.5% | 80-82% | 92-95% | 98-100% |
| txgate | 71.2% | 71.2% | 78-80% | 80-82% |

---

## Test Implementation Checklist

Use this checklist to track progress:

### txgate-crypto (30% gap)
- [ ] Argon2 error paths (derive_key, encrypt_key)
- [ ] FileKeyStore I/O errors (read, write, delete, permissions)
- [ ] normalize_s() both branches (high-S, low-S)
- [ ] Windows cfg(not(unix)) permission code
- [ ] Concurrent FileKeyStore access
- [ ] Unreachable path documentation

### txgate-chain (33% gap)
- [ ] Missing transaction fields (nonce, to, value, data, v) - 5 tests
- [ ] ERC-20 truncated calldata (transfer, approve, transferFrom)
- [ ] RLP malformed structures (truncated, invalid, empty)
- [ ] RLP boundary conditions
- [ ] Erc20Call variant exhaustive coverage
- [ ] RiskLevel Display implementation
- [ ] Token registry address parsing failures

### txgate-policy (31% gap)
- [ ] PolicyCheckResult variant reasons (4 variants)
- [ ] Daily limit boundaries (==limit, overflow, U256::MAX)
- [ ] Daily limit reset across dates
- [ ] None recipient handling
- [ ] Whitelist empty vs. disabled
- [ ] Zero-amount transactions
- [ ] Database operation failures
- [ ] Concurrent history access
- [ ] Duplicate transaction hashes

### txgate (9% gap)
- [ ] CLI command execution errors
- [ ] Invalid config parsing (TOML syntax, missing fields, type errors)
- [ ] Audit log write failures (permissions, disk full)

---

## Alternative: Adjust Coverage Thresholds

If 100% coverage proves impractical, consider these realistic thresholds:

| Crate | Current Threshold | Realistic Threshold | Rationale |
|-------|-------------------|---------------------|-----------|
| txgate-crypto | 100% | 85-90% | Platform-specific code hard to cover |
| txgate-chain | 100% | 90-95% | Some error paths are defensive |
| txgate-policy | 100% | 90-95% | Database error mocking complex |
| txgate | 80% | 75-80% | CLI error paths diverse |

---

## Next Steps

1. **Immediate**: Implement Phase 1 tests (high-impact security paths)
2. **Review**: After Phase 1, re-run coverage and verify improvements
3. **Iterate**: Continue through phases 2-5 until thresholds met
4. **Alternative**: If <95% after Phase 5, consider adjusting thresholds to realistic levels
