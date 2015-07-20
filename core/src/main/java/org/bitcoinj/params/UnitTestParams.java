/*
 * Copyright 2013 Google Inc.
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

package org.bitcoinj.params;

import org.bitcoinj.core.Block;
import org.bitcoinj.core.NetworkParameters;
import org.coinj.api.CoinDefinition;
import org.coinj.api.NetworkMode;

import java.math.BigInteger;

/**
 * Network parameters used by the bitcoinj unit tests (and potentially your own). This lets you solve a block using
 * {@link org.bitcoinj.core.Block#solve()} by setting difficulty to the easiest possible.
 */
public class UnitTestParams extends NetworkParameters {

    private static final int UNIT_TEST_INTERVAL = 10;
    private static final int UNIT_TEST_TARGET_TIMESPAN = 200000000;

    private static final long serialVersionUID = -1429026463997986865L;

    public UnitTestParams(CoinDefinition coinDefinition) {
        super(coinDefinition);
        sharedConstruction(coinDefinition);
    }
    public UnitTestParams(CoinDefinition coinDefinition, NetworkMode mode) {
        super(coinDefinition, mode);
        sharedConstruction(coinDefinition);
    }

    private void sharedConstruction(CoinDefinition coinDefinition) {
        id = coinDefinition.getIdUnitTestNet();
        packetMagic = 0x0b110907;
        addressHeader = coinDefinition.getPubkeyAddressHeader(CoinDefinition.TEST_NETWORK_STANDARD);
        p2shHeader = coinDefinition.getP2shAddressHeader(CoinDefinition.TEST_NETWORK_STANDARD);
        acceptableAddressCodes = new int[] { addressHeader, p2shHeader };
        standardNetworkId = new CoinDefinition.StandardNetworkIdImpl("unitTest");
        maxTarget = coinDefinition.getProofOfWorkLimit(standardNetworkId);
        genesisBlock = createGenesis(this, coinDefinition.getGenesisBlockInfo(CoinDefinition.MAIN_NETWORK_STANDARD));
        genesisBlock.setTime(System.currentTimeMillis() / 1000);
        genesisBlock.setDifficultyTarget(coinDefinition.getEasiestDifficultyTarget());
        genesisBlock.setNonce(1L);
        genesisBlock.solve();
        port = coinDefinition.getPort(CoinDefinition.TEST_NETWORK_STANDARD);
        dumpedPrivateKeyHeader = 128 + addressHeader;
        spendableCoinbaseDepth = 5;
        subsidyDecreaseBlockCount = 100;
        dnsSeeds = null;
    }

    static final class UnitTestParamsFactory extends ParamsFactory<UnitTestParams> {

        @Override
        public UnitTestParams createParams(CoinDefinition coinDefinition) {
            return new UnitTestParams(coinDefinition);
        }

        @Override
        public UnitTestParams createParams(CoinDefinition coinDefinition, NetworkMode mode) {
            return new UnitTestParams(coinDefinition, mode);
        }

    }

    private static final ParamsRegistry<UnitTestParams> paramsRegistry = new ParamsRegistry<UnitTestParams>(new UnitTestParamsFactory());

    public static UnitTestParams get(CoinDefinition def) {
        return paramsRegistry.get(def);
    }

    public static UnitTestParams get() {
        return paramsRegistry.get();
    }

    public static UnitTestParams get(CoinDefinition def, NetworkMode mode) {
        return paramsRegistry.get(def, mode);
    }

    public static UnitTestParams get(NetworkMode mode) {
        return paramsRegistry.get(mode);
    }

    @Override
    public int getInterval(Block block, int height) {
        return UNIT_TEST_INTERVAL;
    }

    @Override
    public int getTargetTimespan(Block block, int height) {
        return UNIT_TEST_TARGET_TIMESPAN;
    }

    @Override
    public String getPaymentProtocolId() {
        return null;
    }

}
