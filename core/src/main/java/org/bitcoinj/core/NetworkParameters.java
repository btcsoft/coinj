/**
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
 * Copyright 2015 BitTechCenter Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.core;

import com.google.common.base.Charsets;
import com.google.common.base.Objects;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.params.UnitTestParams;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptOpCodes;
import org.coinj.api.*;

import javax.annotation.Nullable;
import java.io.ByteArrayOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.HashMap;

import static org.bitcoinj.core.Coin.maxMoney;
import static org.bitcoinj.core.Coin.valueOf;

/**
 * <p>NetworkParameters contains the data needed for working with an instantiation of a Bitcoin chain.</p>
 *
 * <p>This is an abstract class, concrete instantiations can be found in the params package. There are four:
 * one for the main network ({@link MainNetParams}), one for the public test network, and two others that are
 * intended for unit testing and local app development purposes. Although this class contains some aliases for
 * them, you are encouraged to call the static get() methods on each specific params class directly.</p>
 */
public abstract class NetworkParameters implements Serializable {

    private static final long serialVersionUID = -8795923690325415007L;
    /**
     * The protocol version this library implements.
     */
    public final int protocolVersion;

    /**
     * The maximum money to be generated
     */
    public final Coin maxMoney;

    /**
     * A constant shared by the entire network: how large in bytes a block is allowed to be. One day we may have to
     * upgrade everyone to change this, so Bitcoin can continue to grow. For now it exists as an anti-DoS measure to
     * avoid somebody creating a titanically huge but valid block and forcing everyone to download/store it forever.
     */
    public final int maxBlockSize;
    /**
     * A "sigop" is a signature verification operation. Because they're expensive we also impose a separate limit on
     * the number in a block to prevent somebody mining a huge block that has way more sigops than normal, so is very
     * expensive/slow to verify.
     */
    public final int maxBlockSigops;

    private final CoinDefinition coinDefinition;
    private final NetworkExtensionsContainer extensionsContainer;

    // TODO: Seed nodes should be here as well.

    @Nullable
    protected CoinDefinition.StandardNetworkId standardNetworkId;

    protected Block genesisBlock;
    protected BigInteger maxTarget;
    protected int port;
    protected long packetMagic;  // Indicates message origin network and is used to seek to the next message when stream state is unknown.
    protected int addressHeader;
    protected int p2shHeader;
    protected int dumpedPrivateKeyHeader;
    protected byte[] signedMessageHeaderBytes;
    /**
     * The alert signing key (in bitcoin originally owned by Satoshi, and now passed on to Gavin along with a few others).
     */
    protected byte[] alertSigningKey;

    protected String paymentProtocolId;

    /**
     * See getId(). This may be null for old deserialized wallets. In that case we derive it heuristically
     * by looking at the port number.
     */
    protected String id;

    /**
     * The depth of blocks required for a coinbase transaction to be spendable.
     */
    protected int spendableCoinbaseDepth;
    protected int subsidyDecreaseBlockCount;
    
    protected int[] acceptableAddressCodes;
    protected String[] dnsSeeds;
    protected HashMap<Integer, Sha256Hash> checkpoints = new HashMap<Integer, Sha256Hash>();

    protected NetworkParameters(CoinDefinition coinDefinition) {
        this.coinDefinition = coinDefinition;

        protocolVersion = coinDefinition.getProtocolVersion();
        maxMoney = maxMoney(coinDefinition);
        maxBlockSize = coinDefinition.getMaxBlockSize();
        maxBlockSigops = maxBlockSize / 50;

        signedMessageHeaderBytes = generateSignedMessage(coinDefinition);

        extensionsContainer = coinDefinition.createNetworkExtensionsContainer(this);
    }

    protected NetworkParameters(CoinDefinition coinDefinition, NetworkMode networkMode) {
        this.coinDefinition = coinDefinition;

        protocolVersion = coinDefinition.getProtocolVersion();
        maxMoney = maxMoney(coinDefinition);
        maxBlockSize = coinDefinition.getMaxBlockSize();
        maxBlockSigops = maxBlockSize / 50;

        signedMessageHeaderBytes = generateSignedMessage(coinDefinition);

        extensionsContainer = coinDefinition.createNetworkExtensionsContainer(this, networkMode);
    }

    protected static Block createGenesis(NetworkParameters n, GenesisBlockInfo genesisBlockInfo) {
        final Block genesisBlock = new Block(n);
        final Transaction t = new Transaction(n);
        try {
            // A script containing the difficulty bits and the message
            if (genesisBlockInfo.genesisTxInBytes != null) {
                final byte[] bytes = Utils.HEX.decode(genesisBlockInfo.genesisTxInBytes);
                t.addInput(new TransactionInput(n, t, bytes));
            }

            final ByteArrayOutputStream scriptPubKeyBytes = new ByteArrayOutputStream();
            Script.writeBytes(scriptPubKeyBytes, Utils.HEX.decode(genesisBlockInfo.genesisTxOutBytes));
            scriptPubKeyBytes.write(ScriptOpCodes.OP_CHECKSIG);
            t.addOutput(new TransactionOutput(n, t, valueOf(genesisBlockInfo.genesisBlockValue, 0), scriptPubKeyBytes.toByteArray()));
        } catch (Exception e) {
            // Cannot happen.
            throw new RuntimeException(e);
        }
        genesisBlock.addTransaction(t);

        genesisBlock.setDifficultyTarget(genesisBlockInfo.genesisBlockDifficultyTarget);
        genesisBlock.setTime(genesisBlockInfo.genesisBlockTime);
        genesisBlock.setNonce(genesisBlockInfo.genesisBlockNonce);
        if (genesisBlockInfo.genesisMerkleRoot != null) {
            genesisBlock.setMerkleRoot(new Sha256Hash(Utils.HEX.decode(genesisBlockInfo.genesisMerkleRoot)));
        }

        genesisBlockInfo.checkGenesisHash(genesisBlock.getHashAsString());

        return genesisBlock;
    }

    protected static byte[] generateSignedMessage(CoinDefinition coinDefinition) {
        final String signedMessage = (new StringBuilder(30))
                .append(coinDefinition.getSignedMessageName())
                .append(SIGNED_MESSAGE_SUFFIX)
                .toString();
        return signedMessage.getBytes(Charsets.UTF_8);
    }

    protected final void fillProtectedValues() {
        maxTarget = coinDefinition.getProofOfWorkLimit(standardNetworkId);
        addressHeader = coinDefinition.getPubkeyAddressHeader(standardNetworkId);
        dumpedPrivateKeyHeader = coinDefinition.getDumpedPrivateKeyHeader(standardNetworkId);
        p2shHeader = coinDefinition.getP2shAddressHeader(standardNetworkId);
        acceptableAddressCodes = new int[] { addressHeader, p2shHeader };
        port = coinDefinition.getPort(standardNetworkId);
        packetMagic = coinDefinition.getPacketMagic(standardNetworkId);

        genesisBlock = createGenesis(this, coinDefinition.getGenesisBlockInfo(standardNetworkId));

        subsidyDecreaseBlockCount = coinDefinition.getSubsidyDecreaseBlockCount(standardNetworkId);
        spendableCoinbaseDepth = coinDefinition.getSpendableDepth(standardNetworkId);
        dnsSeeds = coinDefinition.getDnsSeeds(standardNetworkId);
        alertSigningKey = Utils.HEX.decode(coinDefinition.getAlertKey(standardNetworkId));
        paymentProtocolId = coinDefinition.getPaymentProtocolId(standardNetworkId);
    }

    /**
     * Blocks with a timestamp after this should enforce BIP 16, aka "Pay to script hash". This BIP changed the
     * network rules in a soft-forking manner, that is, blocks that don't follow the rules are accepted but not
     * mined upon and thus will be quickly re-orged out as long as the majority are enforcing the rule.
     */
    public static final int BIP16_ENFORCE_TIME = 1333238400;

    private static final String SIGNED_MESSAGE_SUFFIX = " Signed Message:\n";

    /**
     * A Java package style string acting as unique ID for these parameters
     */
    public String getId() {
        return id;
    }

    public boolean isMainNet() {
        return id.equals(coinDefinition.getIdMainNet());
    }

    @Nullable
    public CoinDefinition.StandardNetworkId getStandardNetworkId() {
        return standardNetworkId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NetworkParameters other = (NetworkParameters) o;
        return getId().equals(other.getId());
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(getId());
    }

    /** Returns the network parameters for the given string ID or NULL if not recognized. */
    @Nullable
    public static NetworkParameters fromID(String id) {
        final String coinName = extractCoinNameFromID(id);
        CoinDefinition coinDef = CoinLocator.getCoinDefinition(coinName);

        if (coinDef == null) {
            if (coinName.endsWith("j")) {
                coinDef = CoinLocator.getCoinDefinition(coinName.substring(0, coinName.length() - 1));
                if (coinDef == null) {
                    throw new IllegalArgumentException("Can't find coin with name \"" + coinName + "\" for network parameters ID " + id);
                }
            } else {
                throw new IllegalArgumentException("Can't find coin with name \"" + coinName + "\" for network parameters ID " + id);
            }
        }

        if (id.equals(coinDef.getIdMainNet())) {
            return MainNetParams.get(coinDef);
        } else if (id.equals(coinDef.getIdTestNet())) {
            return TestNet3Params.get(coinDef);
        } else if (id.equals(coinDef.getIdUnitTestNet())) {
            return UnitTestParams.get(coinDef);
        } else if (id.equals(coinDef.getIdRegTest())) {
            return RegTestParams.get(coinDef);
        } else {
            return null;
        }
    }

    /** Returns the network parameters for the given string paymentProtocolID or NULL if not recognized. */
    @Nullable
    public static NetworkParameters fromPmtProtocolID(String pmtProtocolId) {
        final CoinDefinition coinDef = CoinLocator.discoverCoinDefinition();

        if (pmtProtocolId.equals(coinDef.getPaymentProtocolId(CoinDefinition.MAIN_NETWORK_STANDARD))) {
            return MainNetParams.get(coinDef);
        } else if (pmtProtocolId.equals(coinDef.getPaymentProtocolId(CoinDefinition.TEST_NETWORK_STANDARD))) {
            return TestNet3Params.get(coinDef);
        } else if (pmtProtocolId.equals(coinDef.getPaymentProtocolId(CoinDefinition.REG_TEST_STANDARD))) {
            return RegTestParams.get(coinDef);
        } else {
            return null;
        }
    }

    private static String extractCoinNameFromID(String id) {
        final int iDotLast = id.lastIndexOf('.');
        final int iDotFirst = id.indexOf('.');
        if (iDotFirst == iDotLast) {
            return id;
        }
        if (iDotLast > 0) {
            id = id.substring(0, iDotLast);
        }
        if (iDotFirst >= 0 && iDotFirst != id.length() - 1) {
            id = id.substring(iDotFirst + 1);
        }
        return id;
    }

    public int getSpendableCoinbaseDepth() {
        return spendableCoinbaseDepth;
    }

    /**
     * Returns true if the block height is either not a checkpoint, or is a checkpoint and the hash matches.
     */
    public boolean passesCheckpoint(int height, Sha256Hash hash) {
        Sha256Hash checkpointHash = checkpoints.get(height);
        return checkpointHash == null || checkpointHash.equals(hash);
    }

    /**
     * Returns true if the given height has a recorded checkpoint.
     */
    public boolean isCheckpoint(int height) {
        Sha256Hash checkpointHash = checkpoints.get(height);
        return checkpointHash != null;
    }

    public int getSubsidyDecreaseBlockCount() {
        return subsidyDecreaseBlockCount;
    }

    /** Returns DNS names that when resolved, give IP addresses of active peers. */
    public String[] getDnsSeeds() {
        return dnsSeeds;
    }

    /**
     * <p>Genesis block for this chain.</p>
     *
     * <p>The first block in every chain is a well known constant shared between all Bitcoin implemenetations. For a
     * block to be valid, it must be eventually possible to work backwards to the genesis block by following the
     * prevBlockHash pointers in the block headers.</p>
     *
     * <p>The genesis blocks for both test and prod networks contain the timestamp of when they were created,
     * and a message in the coinbase transaction. It says, <i>"The Times 03/Jan/2009 Chancellor on brink of second
     * bailout for banks"</i>.</p>
     */
    public Block getGenesisBlock() {
        return genesisBlock;
    }

    public String getGenesisBlockHash() {
        return genesisBlock.getHashAsString();
    }

    /** Default TCP port on which to connect to nodes. */
    public int getPort() {
        return port;
    }

    /** The header bytes that identify the start of a packet on this network. */
    public long getPacketMagic() {
        return packetMagic;
    }

    /**
     * First byte of a base58 encoded address. See {@link org.bitcoinj.core.Address}. This is the same as acceptableAddressCodes[0] and
     * is the one used for "normal" addresses. Other types of address may be encountered with version codes found in
     * the acceptableAddressCodes array.
     */
    public int getAddressHeader() {
        return addressHeader;
    }

    /**
     * First byte of a base58 encoded P2SH address.  P2SH addresses are defined as part of BIP0013.
     */
    public int getP2SHHeader() {
        return p2shHeader;
    }

    /** First byte of a base58 encoded dumped private key. See {@link org.bitcoinj.core.DumpedPrivateKey}. */
    public int getDumpedPrivateKeyHeader() {
        return dumpedPrivateKeyHeader;
    }

    /**
     * How much time in seconds is supposed to pass between "interval" blocks. If the actual elapsed time is
     * significantly different from this value, the network difficulty formula will produce a different value. Both
     * test and production Bitcoin networks use 2 weeks (1209600 seconds).
     */
    public int getTargetTimespan(Block block, int height) {
        return coinDefinition.getTargetTimespan(block, height, standardNetworkId);
    }

    public int getTargetSpacing(Block block, int height) {
        return coinDefinition.getTargetSpacing(block, height, standardNetworkId);
    }

    /**
     * The version codes that prefix addresses which are acceptable on this network. Although Satoshi intended these to
     * be used for "versioning", in fact they are today used to discriminate what kind of data is contained in the
     * address and to prevent accidentally sending coins across chains which would destroy them.
     */
    public int[] getAcceptableAddressCodes() {
        return acceptableAddressCodes;
    }

    /**
     * If we are running in testnet-in-a-box mode, we allow connections to nodes with 0 non-genesis blocks.
     */
    public boolean allowEmptyPeerChain() {
        return true;
    }

    /** How many blocks pass between difficulty adjustment periods. Bitcoin standardises this to be 2015. */
    public int getInterval(Block block, int height) {
        return coinDefinition.getInterval(block, height, standardNetworkId);
    }

    public int getAllowedBlockTimeDrift() {
        return coinDefinition.getAllowedBlockTimeDrift(standardNetworkId);
    }

    /** Maximum target represents the easiest allowable proof of work. */
    public BigInteger getMaxTarget() {
        return maxTarget;
    }

    /**
     * The key used to sign {@link org.bitcoinj.core.AlertMessage}s. You can use {@link org.bitcoinj.core.ECKey#verify(byte[], byte[], byte[])} to verify
     * signatures using it.
     */
    public byte[] getAlertSigningKey() {
        return alertSigningKey;
    }

    public CoinDefinition getCoinDefinition() {
        return coinDefinition;
    }

    public String getPaymentProtocolId() {
        return paymentProtocolId;
    }

    public NetworkExtensionsContainer getExtensionsContainer() {
        return extensionsContainer;
    }

}
