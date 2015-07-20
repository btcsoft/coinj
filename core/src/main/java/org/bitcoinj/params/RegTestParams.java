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

import org.bitcoinj.core.NetworkParameters;
import org.coinj.api.CoinDefinition;
import org.coinj.api.NetworkMode;

/**
 * Network parameters for the regression test mode of bitcoind in which all blocks are trivially solvable.
 */
public class RegTestParams extends NetworkParameters {

    private static final long serialVersionUID = -5587866430996561173L;

    public RegTestParams(CoinDefinition coinDefinition) {
        super(coinDefinition);
        sharedConstruction(coinDefinition);
    }
    public RegTestParams(CoinDefinition coinDefinition, NetworkMode mode) {
        super(coinDefinition, mode);
        sharedConstruction(coinDefinition);
    }

    private void sharedConstruction(CoinDefinition coinDefinition) {
        standardNetworkId = CoinDefinition.REG_TEST_STANDARD;
        id = coinDefinition.getIdRegTest();

        fillProtectedValues();
    }

    static final class RegTestParamsFactory extends ParamsFactory<RegTestParams> {

        @Override
        public RegTestParams createParams(CoinDefinition coinDefinition) {
            return new RegTestParams(coinDefinition);
        }

        @Override
        public RegTestParams createParams(CoinDefinition coinDefinition, NetworkMode mode) {
            return new RegTestParams(coinDefinition, mode);
        }

    }

    private static final ParamsRegistry<RegTestParams> paramsRegistry = new ParamsRegistry<RegTestParams>(new RegTestParamsFactory());

    public static RegTestParams get(CoinDefinition def) {
        return paramsRegistry.get(def);
    }

    public static RegTestParams get() {
        return paramsRegistry.get();
    }

    public static RegTestParams get(CoinDefinition def, NetworkMode mode) {
        return paramsRegistry.get(def, mode);
    }

    public static RegTestParams get(NetworkMode mode) {
        return paramsRegistry.get(mode);
    }

}
