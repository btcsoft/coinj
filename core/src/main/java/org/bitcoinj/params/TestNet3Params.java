/*
 * Copyright 2013 Google Inc.
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

package org.bitcoinj.params;

import org.bitcoinj.core.NetworkParameters;
import org.coinj.api.CoinDefinition;
import org.coinj.api.NetworkMode;

/**
 * Parameters for the testnet, a separate public instance of Bitcoin that has relaxed rules suitable for development
 * and testing of applications and new Bitcoin versions.
 */
public class TestNet3Params extends NetworkParameters {

    private static final long serialVersionUID = -705644188824714011L;

    public TestNet3Params(CoinDefinition coinDefinition) {
        super(coinDefinition);
        sharedConstruction(coinDefinition);
    }
    public TestNet3Params(CoinDefinition coinDefinition, NetworkMode mode) {
        super(coinDefinition, mode);
        sharedConstruction(coinDefinition);
    }

    private void sharedConstruction(CoinDefinition coinDefinition) {
        standardNetworkId = CoinDefinition.TEST_NETWORK_STANDARD;
        id = coinDefinition.getIdTestNet();

        fillProtectedValues();
    }

    static final class TestNetParamsFactory extends ParamsFactory<TestNet3Params> {

        @Override
        public TestNet3Params createParams(CoinDefinition coinDefinition) {
            return new TestNet3Params(coinDefinition);
        }

        @Override
        public TestNet3Params createParams(CoinDefinition coinDefinition, NetworkMode mode) {
            return new TestNet3Params(coinDefinition, mode);
        }

    }

    private static final ParamsRegistry<TestNet3Params> paramsRegistry = new ParamsRegistry<TestNet3Params>(new TestNetParamsFactory());

    public static TestNet3Params get(CoinDefinition def) {
        return paramsRegistry.get(def);
    }

    public static TestNet3Params get() {
        return paramsRegistry.get();
    }

    public static TestNet3Params get(CoinDefinition def, NetworkMode mode) {
        return paramsRegistry.get(def, mode);
    }

    public static TestNet3Params get(NetworkMode mode) {
        return paramsRegistry.get(mode);
    }

}
