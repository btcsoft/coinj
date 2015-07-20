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
 * Parameters for the main production network on which people trade goods and services.
 */
public class MainNetParams extends NetworkParameters {

    private static final long serialVersionUID = 2940756388060073977L;

    public MainNetParams(CoinDefinition coinDefinition) {
        super(coinDefinition);
        sharedConstruction(coinDefinition);
    }

    public MainNetParams(CoinDefinition coinDefinition, NetworkMode networkMode) {
        super(coinDefinition, networkMode);
        sharedConstruction(coinDefinition);
    }

    private void sharedConstruction(CoinDefinition coinDefinition) {
        standardNetworkId = CoinDefinition.MAIN_NETWORK_STANDARD;
        id = coinDefinition.getIdMainNet();
        coinDefinition.initCheckpoints(new CheckpointsMapContainer(checkpoints));

        fillProtectedValues();
    }

    static final class MainNetParamsFactory extends ParamsFactory<MainNetParams> {

        @Override
        public MainNetParams createParams(CoinDefinition coinDefinition) {
            return new MainNetParams(coinDefinition);
        }

        @Override
        public MainNetParams createParams(CoinDefinition coinDefinition, NetworkMode mode) {
            return new MainNetParams(coinDefinition, mode);
        }

    }

    private static final ParamsRegistry<MainNetParams> paramsRegistry = new ParamsRegistry<MainNetParams>(new MainNetParamsFactory());

    public static MainNetParams get(CoinDefinition def) {
        return paramsRegistry.get(def);
    }

    public static MainNetParams get() {
        return paramsRegistry.get();
    }

    public static MainNetParams get(CoinDefinition def, NetworkMode mode) {
        return paramsRegistry.get(def, mode);
    }

    public static MainNetParams get(NetworkMode mode) {
        return paramsRegistry.get(mode);
    }

}
