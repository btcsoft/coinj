/*
 * Copyright 2014 Giannis Dzegoutanis
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

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import org.bitcoinj.core.NetworkParameters;
import org.coinj.api.CoinDefinition;

import java.util.Collection;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Utility class that holds all the registered NetworkParameters types used for Address auto discovery.
 * By default only MainNetParams and TestNet3Params are used. If you want to use TestNet2, RegTestParams or
 * UnitTestParams use the register and unregister the TestNet3Params as they don't have their own address
 * version/type code.
 */
public class Networks {
    /** Registered networks */
    private static final ConcurrentHashMap<CoinDefinition, ImmutableSet<NetworkParameters>> networks =
            new ConcurrentHashMap<CoinDefinition, ImmutableSet<NetworkParameters>>();

    public static ImmutableSet<NetworkParameters> get(CoinDefinition def) {
        Preconditions.checkNotNull(def);
        final ImmutableSet<NetworkParameters> params = networks.get(def);
        if (params == null) {
            return register(def, Lists.newArrayList(TestNet3Params.get(), MainNetParams.get()));
        }
        return params;
    }

    public static void register(CoinDefinition definition, NetworkParameters network) {
        register(definition, Lists.newArrayList(network));
    }

    public static synchronized ImmutableSet<NetworkParameters> register(CoinDefinition definition, Collection<? extends NetworkParameters> params) {
        Preconditions.checkNotNull(params);
        ImmutableSet<NetworkParameters> oldParams = networks.get(definition);
        ImmutableSet.Builder<NetworkParameters> builder = ImmutableSet.builder();
        if (oldParams != null) builder.addAll(oldParams);
        builder.addAll(params);
        final ImmutableSet<NetworkParameters> result = builder.build();
        networks.put(definition, result);
        return result;
    }

    public static synchronized void unregister(CoinDefinition definition, NetworkParameters network) {
        final ImmutableSet<NetworkParameters> params = networks.get(definition);
        if (params != null) {
            ImmutableSet.Builder<NetworkParameters> builder = ImmutableSet.builder();
            for (NetworkParameters np : params) {
                if (np.equals(network))
                    continue;
                builder.add(np);
            }
            networks.put(definition, builder.build());
        }
    }

}
