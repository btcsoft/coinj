/**
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

package org.coinj.api;

import org.bitcoinj.core.*;
import org.bitcoinj.store.WalletProtobufSerializer;

import javax.annotation.Nullable;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.Map;

/**
 * Date: 3/9/15
 * Time: 11:39 PM
 *
 * @author Mikhail Kulikov
 */
public interface CoinDefinition extends Serializable {

    /**
     * Coin name.
     */
    public String getName();

    /**
     * Name for magic sign message (e.g. "DarkCoin Signed Message:\n")
     */
    public String getSignedMessageName();

    /**
     * Coin abbreviated (e.g. BTC).
     */
    public String getTicker();

    /**
     * Coin URI scheme.
     */
    public String getUriScheme();

    /**
     * Coin protocol version.
     */
    public int getProtocolVersion();

    /**
     * Library support for checkpoint files.
     */
    public boolean isCheckpointingSupported();

    /**
     * Checkpoint interval in days.
     */
    public int getCheckpointDaysBack();

    /**
     * Throws runtime exception if check fails.
     * @param checkpointManager checkpoints manager
     * @param checkpoints map of checkpoints with whatever contents type
     * @param networkId (optional) network id, if null defaults to MainNet
     */
    public void checkpointsSanityCheck(CheckpointManager checkpointManager, Map checkpoints, @Nullable StandardNetworkId networkId);

    /**
     * Easiest difficulty target for unit tests.
     */
    public long getEasiestDifficultyTarget();

    /**
     * Amount of time between difficulty switches.
     * @param block last block
     * @param height block's height
     * @param networkId (optional) network id, if null defaults to MainNet
     */
    public int getTargetTimespan(Block block, int height, @Nullable StandardNetworkId networkId);

    /**
     * Spacing between blocks in seconds.
     * @param block last block
     * @param height block's height
     * @param networkId (optional) network id, if null defaults to MainNet
     */
    public int getTargetSpacing(Block block, int height, @Nullable StandardNetworkId networkId);

    /**
     * Number of blocks between difficulty switches.
     * @param block last block
     * @param height block's height
     * @param networkId (optional) network id, if null defaults to MainNet
     */
    public int getInterval(Block block, int height, @Nullable StandardNetworkId networkId);

    /**
     * Number of blocks between difficulty switches for checkpointing process.
     * @param block last block
     * @param height block's height
     * @param networkId (optional) network id, if null defaults to MainNet
     */
    public int getIntervalCheckpoints(Block block, int height, @Nullable StandardNetworkId networkId);

    public int getAllowedBlockTimeDrift(StandardNetworkId networkId);

    /**
     * Block reward counting inflation in satoshis.
     * @param block last block
     * @param prevBlock previous block
     * @param prevHeight previous block's height
     * @param networkId (optional) network id, if null defaults to MainNet
     */
    public long getBlockReward(Block block, Block prevBlock, int prevHeight, StandardNetworkId networkId);

    /**
     * Number of blocks after which block reward will steadily decrease.
     * @param networkId network id (some coins ignore this argument, some don't).
     */
    public int getSubsidyDecreaseBlockCount(StandardNetworkId networkId);

    /**
     * The depth of blocks required for a coinbase transaction to be spendable.
     * @param networkId network id (some coins ignore this argument, some don't).
     */
    public int getSpendableDepth(StandardNetworkId networkId);

    /**
     * The maximum money to be generated.
     */
    public long getMaxCoins();

    /**
     * PoW limit.
     * @param networkId network id (some coins ignore this argument, some don't).
     */
    public BigInteger getProofOfWorkLimit(StandardNetworkId networkId);

    /**
     * If fee is lower than this value (in nanocoins), a default reference client will treat it as if there were no fee.
     */
    public long getDefaultMinTransactionFee();

    /**
     * Any standard (ie pay-to-address) output smaller than this value (in nanocoins) will most likely be rejected by the network.
     */
    public long getDustLimit();

    /**
     * A constant shared by the entire network: how large in bytes a block is allowed to be. One day we may have to
     * upgrade everyone to change this, so Bitcoin can continue to grow. For now it exists as an anti-DoS measure to
     * avoid somebody creating a titanically huge but valid block and forcing everyone to download/store it forever.
     */
    public int getMaxBlockSize();

    /**
     * Coin protocol network connection port.
     * @param networkId network id (some coins ignore this argument, some don't).
     */
    public int getPort(StandardNetworkId networkId);

    /**
     * base58.h CBitcoinAddress::PUBKEY_ADDRESS
     * @param networkId network id (some coins ignore this argument, some don't).
     */
    public int getPubkeyAddressHeader(StandardNetworkId networkId);

    /**
     * Usually 128 + {@link CoinDefinition#getPubkeyAddressHeader(StandardNetworkId)}).
     * @param networkId network id (some coins ignore this argument, some don't).
     */
    public int getDumpedPrivateKeyHeader(StandardNetworkId networkId);

    /**
     * base58.h CBitcoinAddress::SCRIPT_ADDRESS
     * @param networkId network id (some coins ignore this argument, some don't).
     */
    public int getP2shAddressHeader(StandardNetworkId networkId);

    /**
     * checkpoints.cpp Checkpoints::mapCheckpoints
     */
    public void initCheckpoints(CheckpointsContainer container);

    /**
     * Coin protocol packet magic number.
     * @param networkId network id (some coins ignore this argument, some don't).
     */
    public long getPacketMagic(StandardNetworkId networkId);

    /**
     * Genesis block insides.
     * @param networkId network id (some coins ignore this argument, some don't).
     */
    public GenesisBlockInfo getGenesisBlockInfo(StandardNetworkId networkId);

    /**
     * DNS seeds, hard-coded ot otherwise.
     * @param networkId network id (some coins ignore this argument, some don't).
     */
    @Nullable
    public String[] getDnsSeeds(StandardNetworkId networkId);

    /**
     * The alert signing key ( in Bitcoin it was originally owned by Satoshi, and later passed on to Gavin along with a few others).
     * @param networkId network id (some coins ignore this argument, some don't).
     */
    public String getAlertKey(StandardNetworkId networkId);

    /** The string returned by getId() for the main, production network where people trade things. */
    public String getIdMainNet();

    /** The string returned by getId() for the testnet. */
    public String getIdTestNet();

    /** The string returned by getId() for the testnet. */
    public String getIdRegTest();

    /** Unit test network. */
    public String getIdUnitTestNet();

    /** The string used by the payment protocol to represent the main net.
     * @param networkId network id (some coins ignore this argument, some don't).
     * */
    public String getPaymentProtocolId(StandardNetworkId networkId);

    /**
     * Minimum of broadcasting connections to function.
     */
    public int getMinBroadcastConnections();

    /**
     * Allows "dumpprivkey" Bitcoin RPC command.
     */
    public boolean isBitcoinPrivateKeyAllowed();
    public int getAllowedPrivateKey();

    /**
     * A Bloom filter is a probabilistic data structure which can be sent to another client so that it can avoid
     * sending us transactions that aren't relevant to our set of keys. This allows for significantly more efficient
     * use of available network bandwidth and CPU time.
     * @return whether this protocol supports Bloom Filtering.
     */
    public boolean isBloomFilteringSupported(VersionMessage versionInfo);

    /**
     * Returns true if the protocol version and service bits both indicate support for the getutxos message.
     */
    public boolean isGetUTXOsSupported(VersionMessage versionInfo);

    /**
     * Returns true if the clientVersion field is >= Pong.MIN_PROTOCOL_VERSION. If it is then ping() is usable.
     */
    public boolean isPingPongSupported(VersionMessage versionInfo);

    /**
     * Returns true if the version message indicates the sender has a full copy of the block chain,
     * or if it's running in client mode (only has the headers).
     */
    public boolean hasBlockChain(VersionMessage versionInfo);

    @Nullable
    public Integer getNodeNetworkConstant();

    @Nullable
    public Integer getNodeGetUtxosConstant();

    @Nullable
    public Integer getNodeBloomConstant();

    @Nullable
    public Integer getNodePongConstant();

    /**
     * Minimum coin protocol version that supports ping-pong between peers.
     */
    public int getMinPongProtocolVersion();

    /**
     * Minimum coin protocol version that supports bloom filtering.
     */
    public int getMinBloomProtocolVersion();

    @Nullable
    public String getInventoryTypeByCode(int typeCode);

    @Nullable
    public Integer getInventoryTypeOrdinal(String type);

    public interface StandardNetworkId extends Serializable {
        public static final String MAIN_NET = "mainNet";
        public static final String TEST_NET = "testNet";
        public static final String REG_TEST = "regTest";

        public String str();
    }
    public static final class StandardNetworkIdImpl implements StandardNetworkId, Serializable {
        private static final long serialVersionUID = 1L;

        private final String str;

        public StandardNetworkIdImpl(String str) {
            this.str = str;
        }

        @Override
        public String str() {
            return str;
        }

        @Override
        public boolean equals(Object o) {
            return this == o || !(o == null || !(o instanceof StandardNetworkId)) && str.equals(((StandardNetworkId) o).str());
        }

        @Override
        public int hashCode() {
            return str.hashCode();
        }
    }

    public static final StandardNetworkId MAIN_NETWORK_STANDARD = new StandardNetworkIdImpl(StandardNetworkId.MAIN_NET);
    public static final StandardNetworkId TEST_NETWORK_STANDARD = new StandardNetworkIdImpl(StandardNetworkId.TEST_NET);
    public static final StandardNetworkId REG_TEST_STANDARD = new StandardNetworkIdImpl(StandardNetworkId.REG_TEST);

    /*----------------------------------------------------------------------------------------------------------------------------------------------------------------------------*/

    public BlockHasher createBlockHasher();

    public BlockExtension createBlockExtension(Block block);

    public TransactionExtension createTransactionExtension(Transaction transaction);

    public CoinSerializerExtension createCoinSerializerExtension();

    public BlockChainExtension createBlockChainExtension(AbstractBlockChain blockChain);

    public PeerExtension createPeerExtension(Peer peer);

    public PeerGroupExtension createPeerGroupExtension(PeerGroup peerGroup);

    public TransactionConfidenceExtension createTransactionConfidenceExtension(TransactionConfidence transactionConfidence);

    public WalletCoinSpecifics createWalletCoinSpecifics(Wallet wallet);

    public WalletProtobufSerializerExtension createWalletProtobufSerializerExtension(WalletProtobufSerializer walletProtobufSerializer);

    public NetworkExtensionsContainer createNetworkExtensionsContainer(NetworkParameters params);

    public NetworkExtensionsContainer createNetworkExtensionsContainer(NetworkParameters params, @Nullable NetworkMode networkMode);

}
